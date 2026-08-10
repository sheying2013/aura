"""后台任务编排：60s 批量探活、3h 订阅刷新、10s sing-box 崩溃守护、relay 随机轮询。"""
import asyncio
import random
import time
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
            if patch and node.get("exitRisk") is None:
                try:
                    async with _ip_enrich_sem:
                        online = [n for n in db.list_nodes()
                                  if n.get("status") == "online" and n.get("port") != node.get("port")]
                        if node.get("status") == "online":
                            online = [node] + online  # 目标节点在线时优先经它自己查
                        ipr = await asyncio.to_thread(ipinfo.lookup_ippure, online[:8])
                    if ipr.get("exitRisk") is not None:
                        patch["exitRisk"] = ipr["exitRisk"]
                    elif patch.get("exitCountry"):
                        try:
                            async with _ip_enrich_sem:
                                p0 = await asyncio.to_thread(ipinfo.lookup_ping0, cur_ip, online[:10])
                            if p0.get("exitRisk") is not None:
                                patch["exitRisk"] = p0["exitRisk"]
                        except Exception:
                            pass
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

# 连续失败自动处理阈值
# 调保守（2026-08-09 优化）：探活是弱判定（TCP/TLS 握手），单轮抖动/节点风控瞬时拒绝
# 很常见。① 每轮 delay 失败已重试 2 次（吸收 reload/抖动瞬时失败）；② 握手成功即判在线，
# 出口 IP 查询失败不再判死（IP 只是情报，不反证转发能力）；③ 阈值抬高——误停用要人工
# 恢复（约 20 分钟 20 轮连续失败才停），删除阈值仅在节点彻底失联后触发。
DISABLE_AFTER_FAILS = 20  # 连续失败 ≥20 次（约 20 轮×60s）→ 自动停用
DELETE_AFTER_FAILS = 60   # 连续失败 ≥60 次 → 自动删除（保险阈值）
PROBE_CONCURRENCY = 16    # 探活并发上限（降低对 clash API 的瞬时压力，减少超时误判）
_probe_running = False  # 探活进行中标记（P1-2 防并发重叠）
PROBE_DELAY_RETRY = 2     # 每轮 delay 失败重试次数（共 3 次机会，进一步吸收抖动）

async def probe_nodes(ids: Optional[List[str]] = None, all_: bool = True,
                      include_disabled: bool = False) -> List[Dict[str, Any]]:
    """对节点经 clash API 并发探活。返回 {id, tag, ping, status, error}。

    失败计数：连续失败 DISABLE_AFTER_FAILS 次自动停用（status=disabled），
    达到 DELETE_AFTER_FAILS 次自动删除节点并重建配置；成功即清零。

    include_disabled=True（手动测活停用节点）时：临时启用 disabled 节点（生成
    outbound）→ 探活 → 失败恢复 disabled，通过则保持在线。

    互斥：60s 定时循环与手动触发/上一轮重叠时跳过本轮（P1-2：并发探活会让
    失败计数交错累加——在线节点被误判连续失败提前自动停用）。
    """
    global _probe_running
    if _probe_running:
        return []
    _probe_running = True
    try:
        return await _probe_nodes_inner(ids, all_, include_disabled)
    finally:
        _probe_running = False

async def _probe_nodes_inner(ids: Optional[List[str]] = None, all_: bool = True,
                             include_disabled: bool = False) -> List[Dict[str, Any]]:
    import config_manager as cm

    if not cm.is_running():
        return []
    # 防竞态误杀：若 config_manager 正在 apply/reload（_op_lock 被占），clash API 处于
    # 不可达窗口——此时探活必然全部失败。跳过本轮，等 reload 完成后再探活。
    if cm._op_lock.locked():
        return []
    nodes = db.list_nodes()
    if not all_ and ids:
        nodes = [n for n in nodes if n["id"] in ids]
    # 默认跳过 disabled；手动测活（include_disabled）时临时启用
    disabled_ids = [n["id"] for n in nodes if n.get("status") == "disabled"]
    nodes = [n for n in nodes if n.get("status") != "disabled"]
    # 只临时启用本次目标范围内的 disabled 节点（all_=全部；ids=仅指定的），
    # 避免把所有停用节点一起重建进 sing-box 占用端口、探活后又恢复不回来。
    target_disabled = [nid for nid in disabled_ids if (all_ or (ids and nid in ids))]
    if include_disabled and target_disabled:
        for nid in target_disabled:
            db.update_node(nid, {"status": "offline", "consecutiveFails": 0})
        try:
            await cm.apply_config()  # 重建配置含临时启用的节点
        except Exception:
            pass
        # 重新拉取含临时启用节点的列表
        nodes = db.list_nodes()
        if not all_ and ids:
            nodes = [n for n in nodes if n["id"] in ids]
        nodes = [n for n in nodes if n.get("status") != "disabled"]

    async def _probe_one(node: Dict[str, Any]) -> Dict[str, Any]:
        tag = cm.outbound_tag(node["protocol"], node["port"])
        url = (db.get_setting("system", {}) or {}).get("testUrl", "https://www.gstatic.com/generate_204")
        # sing-box clash API 对 http:// 开头 url 会置空并回退测 gstatic（源码 getProxyDelay），
        # 导致探活测的不是配置的 URL、离线判定失真——强制回退 https 语义
        if not url or not str(url).startswith("https://"):
            url = "https://www.gstatic.com/generate_204"

        async def _delay_once() -> Optional[Dict[str, Any]]:
            """单次 clash delay 探测。返回 JSON dict；HTTP 失败/无 delay 返回 None。"""
            try:
                async with httpx.AsyncClient(timeout=6.0) as client:
                    r = await client.get(
                        f"{cm.clash_base()}/proxies/{tag}/delay",
                        params={"url": url, "timeout": "5000"},
                        headers={"Authorization": f"Bearer {cm.get_clash_secret()}"},
                    )
                if r.status_code == 200:
                    return r.json()
            except Exception:
                return None
            return None

        # 失败重试：单轮 delay 抖动（reload 窗口/节点瞬时 RST）不该计一败。
        # 重试 PROBE_DELAY_RETRY 次（共 PROBE_DELAY_RETRY+1 次机会），带指数退避，
        # 仍失败才判离线——阈值随之可以放宽。
        resp = None
        last_msg = None
        for attempt in range(PROBE_DELAY_RETRY + 1):
            if attempt > 0:
                await asyncio.sleep(0.5 * attempt)  # 指数退避：0.5s, 1.0s
            data = await _delay_once()
            if data and data.get("delay"):
                resp = data
                break
            if data:
                last_msg = data.get("message")
        if resp is not None:
            # clash delay 只证明 TCP/TLS 握手能过（HEAD 不校验状态码，握手成功≠可用）。
            # 已有出口 IP 的节点：delay 足够（前轮已全链路验证过）。首次/无 IP 节点：
            # 追加真实出口链路验证（经 inbound 真实请求）——但注意：出口 IP 查询失败
            # **不判死**（2026-08-09 优化）：握手已成功说明节点转发能力正常，出口 IP
            # 只是情报补充（_lazy_enrich_ip 会异步重查），单次 socks5 查询超时/被风控
            # 拒绝不应反过来把可用节点计失败。拿到 IP 顺手落库加速情报。
            cur_ip = node.get("exitIp")
            # 节点自身 server 是域名（如 kookeey 动态IP）→ exitIp 保持域名，不固化解析 IP
            server = ((node.get("rawConfig") or {}).get("server") or "").strip()
            domain_server = bool(server) and not _is_ip_address(server)
            # 已有出口 IP 且不是 hostname → 直接用；域名节点/无 IP 节点触发补查
            if cur_ip and cur_ip not in ("N/A", "1.1.1.1") and _is_ip_address(cur_ip):
                return {"id": node["id"], "tag": tag, "ping": resp.get("delay"),
                        "status": "online"}
            fetched = await _fetch_exit_ip(node)
            if not fetched:
                return {"id": node["id"], "tag": tag, "ping": resp.get("delay"),
                        "status": "online",
                        "error": "出口IP查询失败(握手已通,情报异步补)"}
            # 域名节点：出口 IP 是动态的，只用于情报查询，不落库 exitIp（域名保持）
            if domain_server:
                return {"id": node["id"], "tag": tag, "ping": resp.get("delay"),
                        "status": "online", "exitIpTmp": fetched}
            return {"id": node["id"], "tag": tag, "ping": resp.get("delay"),
                    "status": "online", "exitIp": fetched}
        return {"id": node["id"], "tag": tag, "ping": 0, "status": "offline",
                "error": last_msg or "delay探测失败"}

    if not nodes:
        return []
    # 并发限流：176 节点全 gather 会瞬时打满网络/触发节点风控（之前无上限），
    # 用信号量把同时在建连的探活压到 PROBE_CONCURRENCY 个
    sem = asyncio.Semaphore(PROBE_CONCURRENCY)

    async def _probe_limited(n: Dict[str, Any]) -> Dict[str, Any]:
        async with sem:
            return await _probe_one(n)

    results = await asyncio.gather(*(_probe_limited(n) for n in nodes))
    # 结果落库 + 失败计数 → 自动停用/删除（_probe_one 不落库，避免双重计数）
    # 注意：只标记需要重建，循环结束后统一 apply 一次——每个节点单独 apply_config
    # 会触发大量 reload，sing-box 反复重启累积 TIME-WAIT 导致 bind 冲突（1.7.7 无 SO_REUSEADDR）
    need_rebuild = False
    # 手动测活的 disabled 节点：失败直接恢复 disabled（不计连续失败），成功保持在线
    manual_disabled = set(target_disabled) if include_disabled else set()
    for node, res in zip(nodes, results):
        nid = node["id"]
        if res.get("status") == "online":
            db.update_node_probe(nid, res.get("ping", 0), "online")  # 成功清零
            # 探活真实出口验证拿到的 IP 一并落库（出口链路已验证可用）
            # 域名节点返回 exitIpTmp（临时解析 IP）——不落库，仅同步快照供情报补查
            if res.get("exitIp"):
                db.update_node(nid, {"exitIp": res["exitIp"]})
                node["exitIp"] = res["exitIp"]
            elif res.get("exitIpTmp"):
                node["exitIp"] = res["exitIpTmp"]  # 快照用临时 IP（不写库），enrich 直接用
            # 探活成功 → 同步 node 快照状态为 online，供 _lazy_enrich_ip 风控补查用
            node["status"] = "online"
            # exitIp 已确认 → 情报补查（归属地/风控）可直接进行，无重复出口查询
            _lazy_enrich_ip(node)
            continue
        if nid in manual_disabled:
            # 手动测活失败：恢复 disabled（避免生成 outbound 占用端口）
            db.update_node(nid, {"status": "disabled", "consecutiveFails": 0})
            need_rebuild = True
            continue
        fails = db.update_node_probe(nid, 0, "offline")  # 失败 +1 并返回累计值
        if fails >= DELETE_AFTER_FAILS:
            print(f"[probe] 节点 [{node.get('name')}] 连续失败 {fails} 次，自动删除")
            db.delete_node(nid)
            need_rebuild = True
        elif fails >= DISABLE_AFTER_FAILS:
            print(f"[probe] 节点 [{node.get('name')}] 连续失败 {fails} 次，自动停用")
            db.update_node(nid, {"status": "disabled"})
            need_rebuild = True
    if need_rebuild:
        try:
            await cm.apply_config()
        except Exception:
            pass
    return results


async def _probe_loop() -> None:
    while True:
        await asyncio.sleep(PING_INTERVAL)
        if config_manager.is_running():
            try:
                results = await probe_nodes()
                # apply_config 触发了 reload → 追加 grace period，给 sing-box 重建连接池
                # 的时间，下一轮探活不会紧跟着 reload 窗口误判全挂
                if results and any(r.get("status") == "offline" for r in results):
                    if config_manager._op_lock.locked():
                        await asyncio.sleep(10)  # 等 reload 完成 + 稳定
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

async def _rotate_random_relay() -> None:
    """随机挑一个可用节点作为 relay 出口，经 clash API 运行时切换（零热重载）。

    PUT /proxies/{tag} 只影响新连接、不断已有连接——与固定节点互不干扰。
    轮询时**实时探活候选节点**（clash delay，不走 60s 探活快照）：不通就跳过
    换下一个候选（最多试 10 个），全部不通则维持当前出口不切换——轮询模式
    自动避开已断线节点。返回选中的 outbound tag（无可用节点返回 None）。
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

    # 实时校验：随机打乱候选，逐个 delay 探测，跳过不通的节点
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
    # 运行时切换：selector 支持 PUT /proxies（urltest 不支持，故生成层已改用 selector）
    for rd in db.list_relay_domains():
        rd_tag = f"relay-auto-{rd['id']}"
        try:
            async with httpx.AsyncClient(timeout=3.0) as client:
                await client.put(
                    f"{cm.clash_base()}/proxies/{rd_tag}",
                    json={"name": tag},
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
        if config_manager.is_running():
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
    loop.create_task(_probe_loop())
    loop.create_task(_sub_refresh_loop())
    loop.create_task(_relay_random_loop())
    loop.create_task(_guard_loop())
