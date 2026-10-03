"""后台任务编排：60s 批量探活、3h 订阅刷新、10s sing-box 崩溃守护、relay 随机轮询。"""
import asyncio
import random
import time
from collections import deque
from typing import Any, Dict, List, Optional

import config_manager
import db
import httpx
import stats
import subs_proxy

PING_INTERVAL = 60  # 秒
SUB_REFRESH_INTERVAL = 3 * 60 * 60  # 秒（3 小时）
GUARD_INTERVAL = 10  # 秒
MAX_RESTARTS_PER_MIN = 3

# IP 情报惰性补查：信号量限并发（ipinfo.io 免费 5 万次/月），仅补缺情报的节点
_ip_enrich_sem = asyncio.Semaphore(8)
_ip_enrich_pending: set = set()  # 防同一节点并发重复查
_ip_enrich_last: Dict[str, float] = {}  # 节点 → 上次补查时间（防每轮探活重复查）
_ENRICH_COOLDOWN = 300  # 5 分钟冷却：补查后即使情报不全也不重查（避免每轮 curl 所有节点）

# relay 出口切换时间戳（relay_id → 上次 PUT 切换的 epoch 秒），粘滞超时跨探活轮次保持
_relay_switch_time: Dict[str, float] = {}



def _is_ip_address(s: str) -> bool:
    """判断字符串是否为 IP 地址（v4/v6），非 hostname。"""
    try:
        import ipaddress
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

async def _fetch_exit_ip(node: Dict[str, Any]) -> Optional[str]:
    """经节点自身代理查真实出口 IP。

    - mixed entry（socks5 入口）：经 inbound socks5 代理请求 api.ipify.org
    - ss entry（Shadowsocks 入口）：无 SOCKS5 握手协议——单跳 ss 落地节点
      server 域名解析 IP 即出口（如 kookeey.info 系），直接 DNS 解析 rawConfig.server。
    """
    port = node.get("port")
    user = node.get("authUser") or "user"
    passwd = node.get("authPass") or "pass"
    if not port:
        return None
    import asyncio as _aio
    entry = node.get("entryProto") or "mixed"

    def _run() -> Optional[str]:
        import socket
        # ss entry：Shadowsocks 无 SOCKS5 握手，单跳节点 server 即出口
        if entry == "ss":
            server = ((node.get("rawConfig") or {}).get("server") or "").strip()
            if not server:
                return None
            try:
                return socket.gethostbyname(server)  # 域名 → 出口 IP
            except Exception:
                return None
        # mixed entry：SOCKS5 握手 → HTTP GET api.ipify.org
        try:
            # 构造 socks5 代理请求：手工 SOCKS5 握手 → HTTP GET api.ipify.org
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect(("127.0.0.1", int(port)))
            # SOCKS5 握手 (no auth)
            s.send(b"\x05\x01\x00")
            resp = s.recv(2)
            if resp != b"\x05\x00":
                # try user/pass auth
                s.close()
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect(("127.0.0.1", int(port)))
                s.send(b"\x05\x01\x02")
                resp = s.recv(2)
                if resp != b"\x05\x02":
                    s.close()
                    return None
                ubytes = user.encode()
                pbytes = passwd.encode()
                s.send(b"\x01" + bytes([len(ubytes)]) + ubytes + bytes([len(pbytes)]) + pbytes)
                auth_resp = s.recv(2)
                if auth_resp != b"\x01\x00":
                    s.close()
                    return None
            # SOCKS5 CONNECT to api.ipify.org:80
            host = b"api.ipify.org"
            s.send(b"\x05\x01\x00\x03" + bytes([len(host)]) + host + b"\x00\x50")
            conn_reply = s.recv(10)  # connection reply
            if len(conn_reply) < 2 or conn_reply[1] != 0x00:
                s.close()
                return None
            # HTTP GET
            s.send(b"GET / HTTP/1.0\r\nHost: api.ipify.org\r\n\r\n")
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            # parse HTTP response
            parts = data.split(b"\r\n\r\n", 1)
            if len(parts) == 2:
                ip = parts[1].strip().decode()
                if ip and len(ip) < 50 and not ip.startswith("<"):
                    return ip
            return None
        except Exception:
            return None

    return await _aio.to_thread(_run)


def _lazy_enrich_ip(node: Dict[str, Any]) -> None:
    """探活成功后惰性补查出口 IP 情报（归属地/评分 + ippure/ping0 风控值），已齐全则跳过。

    节点 exitIp 为空/N/A/1.1.1.1（新导入未查过出口）时，先经节点自身代理查真实出口 IP
    并落库，再补情报——否则探活永远触发不了 IP 质量数据（原逻辑直接 return 是根因）。
    """
    ip = node.get("exitIp")
    nid = node["id"]
    # 节点 server 是域名（动态 IP，如 kookeey）→ exitIp 保持域名；解析 IP 仅临时查情报
    server = ((node.get("rawConfig") or {}).get("server") or "").strip()
    domain_server = bool(server) and not _is_ip_address(server)
    if not ip or ip in ("N/A", "1.1.1.1"):
        ip = None  # 需先查出口 IP
    # exitIp 存的是 hostname（如 rooster465.autos）→ ipinfo 对 hostname 的
    # country 解析常失败 → 视为无效 IP，重新通过代理查真实 IP
    if ip and not _is_ip_address(ip):
        ip = None
    # 情报已齐全（域名节点同样适用：之前已用解析 IP 查过 type/risk）→ 跳过
    if (ip or domain_server) and node.get("exitCountry") and node.get("exitType") and node.get("exitRisk") is not None:
        return  # 情报已齐全
    if nid in _ip_enrich_pending:
        return
    # 冷却：上次补查后 5 分钟内不重查（情报不全时避免每轮探活重复 curl 所有节点）
    if time.time() - _ip_enrich_last.get(nid, 0) < _ENRICH_COOLDOWN:
        return
    _ip_enrich_pending.add(nid)

    async def _do() -> None:
        cur_ip = ip  # 闭包捕获外层 ip（内层不重新赋值，避免 UnboundLocalError）
        try:
            # server 是域名（动态 IP）→ exitIp 保持域名不固化；解析 IP 仅临时查情报
            server = ((node.get("rawConfig") or {}).get("server") or "").strip()
            domain_server = bool(server) and not _is_ip_address(server)
            # 无出口 IP → 经节点自身代理查询（探活已确认在线，代理应可达）
            if not cur_ip:
                async with _ip_enrich_sem:
                    fetched = await _fetch_exit_ip(node)
                if not fetched:
                    return
                cur_ip = fetched
                # 域名节点：临时解析 IP 不写 exitIp（动态 IP 固化会过期）
                if not domain_server:
                    db.update_node(nid, {"exitIp": cur_ip})
            async with _ip_enrich_sem:
                import ipinfo
                info = await asyncio.to_thread(ipinfo.lookup, cur_ip)
            patch = {k: info[k] for k in
                     ("exitCountry", "exitFlag", "exitCity", "exitType", "exitScore")
                     if k in info}
            # 风控值：优先 ippure（fraudScore，无验证稳定），失败再 ping0
            if node.get("exitRisk") is None:
                try:
                    async with _ip_enrich_sem:
                        online = [n for n in db.list_nodes()
                                  if n.get("status") == "online"
                                  and (n.get("entryProto") or "mixed") == "mixed"]
                        target = next((n for n in online if n["id"] == nid), None)
                        ipr = {}
                        if target:
                            try:
                                ipr = await asyncio.to_thread(ipinfo.lookup_ippure, [target])
                            except Exception:
                                ipr = {}
                    if ipr.get("exitIp") == cur_ip and ipr.get("exitRisk") is not None:
                        patch["exitRisk"] = ipr["exitRisk"]
                    else:
                        async with _ip_enrich_sem:
                            p0 = await asyncio.to_thread(ipinfo.lookup_ping0, cur_ip, online[:10])
                        if p0.get("exitRisk") is not None:
                            patch["exitRisk"] = p0["exitRisk"]
                except Exception:
                    pass
            if patch:
                db.update_node(nid, patch)
        except Exception:
            pass
        finally:
            _ip_enrich_pending.discard(nid)
            _ip_enrich_last[nid] = time.time()  # 记录补查时间（冷却用）
            if len(_ip_enrich_last) > 5000:  # LRU 淘汰最旧 20%（防全清后冷却重置风暴）
                oldest = sorted(_ip_enrich_last, key=_ip_enrich_last.get)[:1000]
                for k in oldest:
                    del _ip_enrich_last[k]

    asyncio.create_task(_do())

# 崩溃守护状态
_restart_times: List[float] = []
_guard_paused = False


# ---------- 探活 ----------

# 后台弱探活需要完整观察期；仅自动停用，节点数据由用户决定是否删除。
DISABLE_AFTER_FAILS = 20  # 连续失败 ≥20 次（约 20 轮×60s）→ 结合窗口存活率判停用
MIN_FAILURE_SECONDS = 20 * 60  # 后台连续失败至少持续 20 分钟，避免短周期误停
PROBE_CONCURRENCY = 16    # 探活并发上限（降低对 clash API 的瞬时压力，减少超时误判）
_probe_running = False  # 探活进行中标记（P1-2 防并发重叠）
PROBE_DELAY_RETRY = 2     # 每轮 delay 失败重试次数（共 3 次机会，进一步吸收抖动）

# 后台样本满足连败、完整窗口与持续时间三项条件才停用。
_PROBE_WINDOW = 30
_PROBE_DISABLE_RATE_FAST = 0.3
_probe_hist: Dict[str, Any] = {}
_probe_failure_since: Dict[str, float] = {}
_probe_tags: Dict[str, tuple] = {}
_scheduler_tasks: set = set()


def _record_probe(node_id: str, ok: bool) -> None:
    """记录一轮探活结果到该节点滑窗（固定长度，自动淘汰最旧）。"""
    d = _probe_hist.get(node_id)
    if d is None:
        d = deque(maxlen=_PROBE_WINDOW)
        _probe_hist[node_id] = d
    d.append(1 if ok else 0)


def _probe_window_rate(node_id: str) -> tuple:
    """返回 (窗口内探活次数, 存活率)。无记录返回 (0, 1.0)——没观察过的节点按不罚处理。"""
    d = _probe_hist.get(node_id)
    if not d:
        return 0, 1.0
    return len(d), sum(d) / len(d)


def _prune_probe_hist(valid_ids: set) -> None:
    """清理已删节点的滑窗记录（防内存随批量导入/删除无限增长）。

    仅在记录数明显超过存活节点数时执行（O(1) 判断），正常轮次零开销。
    """
    if len(_probe_hist) <= len(valid_ids) + 500:
        return
    for k in list(_probe_hist.keys()):
        if k not in valid_ids:
            _reset_probe_observation(k)

async def probe_nodes(ids: Optional[List[str]] = None, all_: bool = True,
                      include_disabled: bool = False, *, manual: bool = True) -> List[Dict[str, Any]]:
    """互斥探活；手动失败只展示，后台失败才累计观察与停用。重叠返回空列表。"""
    global _probe_running
    if _probe_running:
        return []
    _probe_running = True
    try:
        return await _probe_nodes_inner(ids, all_, include_disabled, manual=manual)
    finally:
        _probe_running = False


async def _probe_one(node: Dict[str, Any], client: "httpx.AsyncClient",
                     url: str, hdrs: Dict[str, str], *, manual: bool) -> Dict[str, Any]:
    """限流槽内完成重试与后台重确认；管理 API 故障属于 unknown。"""
    tag = config_manager.outbound_tag(node["protocol"], node["port"])
    result = {"id": node["id"], "tag": tag, "ping": 0, "status": "offline"}
    attempts = PROBE_DELAY_RETRY + 1 + (0 if manual else 1)
    for attempt in range(attempts):
        if attempt:
            await asyncio.sleep(0.5 * min(attempt, 2))
        try:
            r = await client.get(
                f"{config_manager.clash_base()}/proxies/{tag}/delay",
                params={"url": url, "timeout": "8000" if attempt > PROBE_DELAY_RETRY else "5000"},
                headers=hdrs,
            )
            if r.status_code in (401, 403, 404):
                return {**result, "status": "unknown", "error": f"clash API HTTP {r.status_code}"}
            try:
                data = r.json()
            except (ValueError, TypeError):
                return {**result, "status": "unknown", "error": "clash API 返回无效 JSON"}
            if not isinstance(data, dict):
                return {**result, "status": "unknown", "error": "clash API 返回无效结果"}
            if r.status_code == 200 and data.get("delay") is not None:
                delay = data["delay"]
                if isinstance(delay, bool) or not isinstance(delay, (int, float)) or delay < 0:
                    return {**result, "status": "unknown", "error": "clash API 返回无效 delay"}
                return {**result, "status": "online", "ping": int(delay)}
            if not data.get("message"):
                return {**result, "status": "unknown", "error": f"clash API HTTP {r.status_code} 无探活结果"}
            result["error"] = str(data["message"])
        except (httpx.HTTPError, OSError) as exc:
            return {**result, "status": "unknown", "error": f"clash API 不可达: {exc}"}
    return result


def _reset_probe_observation(node_id: str) -> None:
    _probe_hist.pop(node_id, None)
    _probe_failure_since.pop(node_id, None)
    _probe_tags.pop(node_id, None)


async def _probe_round_valid(generation: int) -> bool:
    running = await asyncio.to_thread(config_manager.is_running)
    return (running and not config_manager._op_lock.locked()
            and config_manager.operation_generation() == generation)


async def _probe_nodes_inner(ids: Optional[List[str]] = None, all_: bool = True,
                             include_disabled: bool = False, *, manual: bool = True) -> List[Dict[str, Any]]:
    import config_manager as cm

    if not await asyncio.to_thread(cm.is_running) or cm._op_lock.locked():
        return []
    generation = cm.operation_generation()
    nodes = db.list_nodes()
    _prune_probe_hist({n["id"] for n in nodes})
    _test_url = (db.get_setting("system", {}) or {}).get("testUrl", "https://www.gstatic.com/generate_204")
    if not _test_url or not str(_test_url).startswith("https://"):
        _test_url = "https://www.gstatic.com/generate_204"
    _hdrs = {"Authorization": f"Bearer {cm.get_clash_secret()}"}
    if not all_ and ids:
        nodes = [n for n in nodes if n["id"] in ids]
    skipped = []
    targets = []
    for node in nodes:
        if node.get("status") != "disabled":
            targets.append(node)
        elif include_disabled and node.get("disabledAuto"):
            targets.append(node)
        elif include_disabled:
            skipped.append({"id": node["id"], "tag": cm.outbound_tag(node["protocol"], node["port"]),
                            "ping": 0, "status": "disabled", "error": "用户手动停用，请先启用节点再测活"})
    nodes = targets

    if not nodes:
        return skipped
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    async with httpx.AsyncClient(timeout=10.0) as probe_client:
        async def _probe_limited(n: Dict[str, Any]) -> Dict[str, Any]:
            async with sem:
                return await _probe_one(n, probe_client, _test_url, _hdrs,
                                        manual=manual and n.get("status") != "disabled")
        results = await asyncio.gather(*(_probe_limited(n) for n in nodes))
    if not await _probe_round_valid(generation):
        return []
    need_rebuild = False
    for node, res in zip(nodes, results):
        if cm._op_lock.locked() or cm.operation_generation() != generation:
            break
        nid = node["id"]
        if res["status"] == "unknown":
            continue
        expected = {"expected_port": node["port"], "expected_protocol": node["protocol"]}
        tag_version = (node["port"], node["protocol"])
        if _probe_tags.get(nid, tag_version) != tag_version:
            _reset_probe_observation(nid)
        _probe_tags[nid] = tag_version
        if node.get("status") == "disabled":
            if res["status"] != "online":
                res["status"] = "disabled"
                continue
            changed = db.revive_node_probe(nid, res["ping"], **expected)
            if changed is None:
                res.update(status="unknown", error="节点状态或探活 tag 已变，本轮结果已跳过")
                continue
            _reset_probe_observation(nid)
            _record_probe(nid, True)
            need_rebuild = True
        else:
            fails = db.update_node_probe(nid, res["ping"], res["status"],
                                         count_failure=not manual, **expected)
            if fails is None:
                res.update(status="unknown", error="节点状态或探活 tag 已变，本轮结果已跳过")
                continue
            if res["status"] == "online":
                _probe_failure_since.pop(nid, None)
                if not manual:
                    _record_probe(nid, True)
            elif not manual:
                _record_probe(nid, False)
                since = _probe_failure_since.setdefault(nid, time.monotonic())
                tot, rate = _probe_window_rate(nid)
                current = db.get_node(nid)
                if (fails >= DISABLE_AFTER_FAILS and tot >= _PROBE_WINDOW
                        and rate <= _PROBE_DISABLE_RATE_FAST
                        and time.monotonic() - since >= MIN_FAILURE_SECONDS
                        and current and current["status"] == "offline"
                        and current["consecutiveFails"] == fails
                        and current["port"] == node["port"]
                        and current["protocol"] == node["protocol"]):
                    if db.disable_node_after_probe(nid, expected_fails=fails, **expected):
                        res["status"] = "disabled"
                        need_rebuild = True
        if res["status"] == "online":
            node["status"] = "online"
            _lazy_enrich_ip(node)
    if need_rebuild:
        try:
            await cm.apply_config()
        except Exception:
            pass
    try:
        await _sync_relay_exits_after_probe(results)
    except Exception:
        pass
    return results + skipped


# ---------- relay 出口粘滞超时 ----------

async def _sync_relay_exits_after_probe(probe_results: Optional[List[Dict[str, Any]]] = None) -> None:
    """探活后按粘滞超时刷新 relay 出口（selector 运行时切换，零热重载）。

    语义：每个 relay-auto-<id> 出口记录切换时间；距离上次切换 < 粘滞时长 →
    保持不动；已超时 → 在当前分组可达节点里挑延迟最优（clash delay）切换。
    关闭粘滞 → 每次探活都切最优。设置是唯一真源（与 upsert 一致）。
    """
    import config_manager as cm
    import httpx

    settings = db.get_setting("system", {}) or {}
    sticky_enabled = bool(settings.get("stickyEnabled"))
    sticky_timeout = (settings.get("stickyTimeout") or "5m").strip().lower()
    # 解析粘滞时长（30s / 5m / 10m / 1h）
    try:
        unit = sticky_timeout[-1]
        val = float(sticky_timeout[:-1])
        if unit == "s":
            sticky_sec = val
        elif unit == "m":
            sticky_sec = val * 60
        elif unit == "h":
            sticky_sec = val * 3600
        else:
            sticky_sec = 300
    except (ValueError, IndexError):
        sticky_sec = 300
    sticky_sec = max(sticky_sec, 5)

    relays = db.list_relay_domains()
    if not relays:
        return
    # 节点快照：name/group/status/协议端口 tag（排除停用）
    nodes = [n for n in db.list_nodes() if n.get("status") != "disabled"]
    node_by_tag = {cm.outbound_tag(n["protocol"], n["port"]): n for n in nodes}
    hdrs = {"Authorization": f"Bearer {cm.get_clash_secret()}"}
    test_url = settings.get("testUrl", "https://www.gstatic.com/generate_204")
    if not test_url or not str(test_url).startswith("https://"):
        test_url = "https://www.gstatic.com/generate_204"

    async def _current(rd_tag: str, client: "httpx.AsyncClient") -> Optional[str]:
        try:
            r = await client.get(f"{cm.clash_base()}/proxies/{rd_tag}", headers=hdrs)
            if r.status_code == 200:
                now = r.json().get("now")
                return now if now and now != rd_tag else None
        except Exception:
            pass
        return None

    # 本轮结果（包含失败）按 tag 缓存；同一个节点不随 relay 数量重复测。
    delay_cache = {r["tag"]: r.get("ping", 0) if r.get("status") == "online" else None
                   for r in (probe_results or []) if r.get("tag")}
    generation = cm.operation_generation()
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)
    async with httpx.AsyncClient(timeout=10.0) as client:
        missing = {t for t, n in node_by_tag.items() if t not in delay_cache
                   and any("ALL" in (rd.get("groups") or ["ALL"])
                           or n.get("group") in (rd.get("groups") or ["ALL"]) for rd in relays)}

        async def measure(t: str) -> None:
            async with sem:
                r = await _probe_one(node_by_tag[t], client, test_url, hdrs, manual=True)
                delay_cache[t] = r["ping"] if r["status"] == "online" else None

        await asyncio.gather(*(measure(t) for t in missing))
        if not await _probe_round_valid(generation):
            return
        for rd in relays:
            rd_tag = f"relay-auto-{rd['id']}"
            sel_groups = rd.get("groups") or ["ALL"]
            targets = [
                t for t, n in node_by_tag.items()
                if ("ALL" in sel_groups or n.get("group") in sel_groups)
            ]
            if not targets:
                continue
            cur = await _current(rd_tag, client)
            # 粘滞期内：保持当前出口（当前出口必须仍在本组可达池，否则强制切换）
            if sticky_enabled and cur and cur in targets:
                last = _relay_switch_time.get(rd["id"], 0)
                if time.time() - last < sticky_sec:
                    continue
            if cm._op_lock.locked() or cm.operation_generation() != generation:
                return
            latest = {cm.outbound_tag(n["protocol"], n["port"]): n for n in db.list_nodes()
                      if n.get("status") != "disabled"}
            targets = [t for t in targets if t in latest
                       and ("ALL" in sel_groups or latest[t].get("group") in sel_groups)]
            if not targets:
                continue
            # 挑延迟最优（当前出口也参与比较；全不通则维持当前不动，不静默跳过）
            best, best_delay = None, None
            for t in targets:
                d = delay_cache.get(t)
                if d is not None and (best_delay is None or d < best_delay):
                    best, best_delay = t, d
            if best is None:
                if cur:
                    print(f"[relay-exit] {rd_tag} 候选全被瞬时判定不通，维持当前出口 {cur}")
                continue
            if best == cur:
                continue
            try:
                r = await client.put(f"{cm.clash_base()}/proxies/{rd_tag}",
                                     json={"name": best}, headers=hdrs)
                if r.status_code in (200, 204):
                    _relay_switch_time[rd["id"]] = time.time()
                    print(f"[relay-exit] {rd_tag} 出口 → {best} (delay {best_delay}ms)")
            except Exception as e:
                print(f"[relay-exit] PUT 切换 {rd_tag} 失败: {e}")


async def _probe_loop() -> None:
    while True:
        # 探活间隔可配置（系统设置「自动延迟探活间隔（秒）」），下限 10s 防误配
        settings = db.get_setting("system", {}) or {}
        try:
            interval = max(int(settings.get("probeInterval") or PING_INTERVAL), 10)
        except (TypeError, ValueError):
            interval = PING_INTERVAL
        await asyncio.sleep(interval)
        if await asyncio.to_thread(config_manager.is_running):
            try:
                results = await probe_nodes(manual=False)
                # apply_config 触发了 reload → 追加 grace period，给 sing-box 重建连接池
                # 的时间，下一轮探活不会紧跟着 reload 窗口误判全挂
                if results and any(r.get("status") == "offline" for r in results):
                    if config_manager._op_lock.locked():
                        await asyncio.sleep(10)  # 等 reload 完成 + 稳定
            except Exception:
                pass


# ---------- 停用节点自动复活（波动节点误停自愈） ----------

REVIVE_INTERVAL = 600  # 秒：停用节点自动复查周期（网络恢复后自动回池）


async def _disabled_revive_loop() -> None:
    """只复查自动停用的 outbound；失败不写库、不重载，成功由 CAS 恢复。"""
    while True:
        await asyncio.sleep(REVIVE_INTERVAL)
        try:
            if not await asyncio.to_thread(config_manager.is_running):
                continue
            if config_manager._op_lock.locked():
                continue  # apply/reload 窗口 clash API 不可达，下轮再查
            disabled = [n["id"] for n in db.list_nodes()
                        if n.get("status") == "disabled" and n.get("disabledAuto")]
            if not disabled:
                continue
            results = await probe_nodes(ids=disabled, all_=False, include_disabled=True, manual=False)
            if not results:
                continue  # 与定时探活重叠（互斥跳过）或 sing-box 不可用
            revived = sum(1 for r in results if r.get("status") == "online")
            if revived:
                print(f"[probe] 自动复查：{revived}/{len(results)} 个停用节点恢复在线，自动回池")
        except Exception:
            pass


# ---------- 订阅刷新 ----------

async def _sub_refresh_loop() -> None:
    while True:
        await asyncio.sleep(SUB_REFRESH_INTERVAL)
        # settings.autoRefresh=false 时跳过自动刷新（前端「每 6 小时自动刷新」开关）
        settings = db.get_setting("system", {}) or {}
        if settings.get("autoRefresh") is False:
            continue
        try:
            await subs_proxy.refresh_subs(all_=True)
        except Exception:
            pass


# ---------- relay 域名随机轮询（注册机/爬虫场景） ----------

RANDOM_ROTATE_DEFAULT_INTERVAL = 30  # 秒（默认随机轮询间隔）

def outbound_tag_for(node: Dict[str, Any]) -> str:
    """节点 → outbound tag（与 config_manager.outbound_tag 一致，避免循环依赖）。"""
    return f"out-{node.get('protocol')}-{node.get('port')}"

async def _rotate_random_relay() -> Optional[str]:
    """随机挑一个可用节点作为 relay 出口，经 clash API 运行时切换（零热重载）。

    PUT /proxies/{tag} 只影响新连接、不断已有连接——与固定节点互不干扰。
    轮询时**实时探活候选节点**（clash delay，不走 60s 探活快照）：不通就跳过
    换下一个候选（最多试 10 个），全部不通则维持当前出口不切换——轮询模式
    自动避开已断线节点。**按每个 relay 的分组过滤候选**（与 config 生成一致），
    避免把分组外的节点切到该 relay 的出口。返回选中的 outbound tag（无可用节点返回 None）。
    """
    import config_manager as cm
    import httpx

    nodes = [n for n in db.list_nodes() if n.get("status") != "disabled"]
    if not nodes:
        return None
    # 可用池：优先在线节点（探活快照），无在线节点才用全部非停用
    online = [n for n in nodes if n.get("status") == "online"]
    pool = online or nodes
    test_url = (db.get_setting("system", {}) or {}).get("testUrl", "https://www.gstatic.com/generate_204")
    # 同 probe：sing-box 对 http:// url 置空回退 gstatic，强制 https 语义
    if not test_url or not str(test_url).startswith("https://"):
        test_url = "https://www.gstatic.com/generate_204"
    hdrs = {"Authorization": f"Bearer {cm.get_clash_secret()}"}

    async def _is_alive(node: Dict[str, Any]) -> bool:
        """实时探测节点连通性（clash API delay，2s 超时）。"""
        tag = outbound_tag_for(node)
        try:
            async with httpx.AsyncClient(timeout=4.0) as client:
                r = await client.get(
                    f"{cm.clash_base()}/proxies/{tag}/delay",
                    params={"url": test_url, "timeout": "2000"},
                    headers=hdrs,
                )
            return r.status_code == 200 and r.json().get("delay") is not None
        except Exception:
            return False

    def _group_candidates(rd: Dict[str, Any]) -> List[Dict[str, Any]]:
        """按 relay 的 groups 过滤候选池（与 config 生成一致：ALL 或包含该分组）。"""
        sel_groups = rd.get("groups") or ["ALL"]
        return [n for n in pool if "ALL" in sel_groups or n.get("group") in sel_groups]

    # 先随机挑一个可用节点（全局池），各 relay 再按分组过滤/回退
    candidates = list(pool)
    random.shuffle(candidates)
    chosen = None
    for node in candidates[:10]:
        if await _is_alive(node):
            chosen = node
            break
    if chosen is None:
        print("[relay-rotate] 本轮候选节点全部不通，维持当前出口")
        return None
    tag = outbound_tag_for(chosen)
    # 运行时切换：selector 支持 PUT /proxies（urltest 不支持，故生成层已改用 selector）。
    # 每个 relay 独立：分组内有可达候选 → 分组内随机切换；否则回退全局已选出口。
    for rd in db.list_relay_domains():
        rd_tag = f"relay-auto-{rd['id']}"
        rd_cands = _group_candidates(rd)
        target = tag
        if rd_cands:
            # 分组内随机挑（与全局选择互相独立：每个 relay 有各自的分组轮询出口）
            g = list(rd_cands)
            random.shuffle(g)
            for node in g[:10]:
                if await _is_alive(node):
                    target = outbound_tag_for(node)
                    break
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.put(
                    f"{cm.clash_base()}/proxies/{rd_tag}",
                    json={"name": target},
                    headers=hdrs,
                )
        except Exception as e:
            print(f"[relay-rotate] PUT 切换 {rd_tag} 失败: {e}")
    settings = db.get_setting("system", {}) or {}
    settings["randomRotateCurrent"] = tag
    db.set_setting("system", settings)
    print(f"[relay-rotate] 随机出口 → {chosen.get('name')} ({tag})")
    return tag


async def _relay_random_loop() -> None:
    """随机轮询循环：开启时按设定间隔随机挑一个可用节点并运行时切换出口。

    面板层实现（sing-box 无随机 outbound）：selector + PUT /proxies 运行时切换，
    只影响新连接、不断已有连接（不热重载）。
    关闭随机轮询后：selector 保持当前选中（或由探活调度切到延迟最优）。
    """
    while True:
        settings = db.get_setting("system", {}) or {}
        interval = int(settings.get("randomRotateInterval") or RANDOM_ROTATE_DEFAULT_INTERVAL)
        await asyncio.sleep(max(interval, 5))
        try:
            settings = db.get_setting("system", {}) or {}
            if not settings.get("randomRotateEnabled"):
                continue
            await _rotate_random_relay()
        except Exception as e:
            print(f"[relay-rotate] 失败: {e}")


# ---------- 崩溃守护 ----------

async def _guard_loop() -> None:
    global _guard_paused, _restart_times
    while True:
        await asyncio.sleep(GUARD_INTERVAL)
        # 进程对象不存在（从未启动/已正常停止）→ 不处理
        if config_manager.get_proc() is None:
            continue
        # is_running() 基于收割任务判断：进程已退出且被 _reap_proc 收割 → False
        # （asyncio 的 Process.returncode 不调 wait() 永远不更新，直接读它进程死了
        #   也显示"活着"，守护会漏重启。此判断依赖 config_manager 的收割任务）
        if await asyncio.to_thread(config_manager.is_running):
            if _guard_paused:
                _guard_paused = False
            continue
        # 进程已退出 → 需要重启
        now = time.time()
        _restart_times.append(now)
        _restart_times = [t for t in _restart_times if now - t < 60]
        if len(_restart_times) > MAX_RESTARTS_PER_MIN:
            # 限流：进入 60s 冷却，等时间推移后自动恢复
            if not _guard_paused:
                print("[guard] sing-box 崩溃过于频繁，进入 60s 冷却")
            _guard_paused = True
            continue
        _guard_paused = False
        try:
            await config_manager.start()
        except Exception:
            pass


# ---------- 生命周期 ----------

def start_scheduler(loop: asyncio.AbstractEventLoop) -> None:
    if any(not task.done() for task in _scheduler_tasks):
        return
    for worker in (_probe_loop, _sub_refresh_loop, _relay_random_loop,
                   _guard_loop, _disabled_revive_loop):
        task = loop.create_task(worker())
        _scheduler_tasks.add(task)
        task.add_done_callback(_scheduler_tasks.discard)


async def stop_scheduler() -> None:
    tasks = list(_scheduler_tasks)
    for task in tasks:
        task.cancel()
    await asyncio.gather(*tasks, return_exceptions=True)
    _scheduler_tasks.difference_update(tasks)
