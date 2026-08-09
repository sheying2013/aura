"""后台任务编排：60s 批量探活、3h 订阅刷新、10s sing-box 崩溃守护、relay 随机轮询。"""
import asyncio
import random
import time
from typing import Any, Dict, List, Optional

import config_manager
import db
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


async def _fetch_exit_ip(node: Dict[str, Any]) -> Optional[str]:
    """经节点自身 socks5 代理查真实出口 IP（复用 app.py 手动查出口的逻辑）。

    仅探活确认在线后调用：节点不可用则代理连不上，返回 None。
    """
    port = node.get("port")
    user = node.get("authUser") or "user"
    passwd = node.get("authPass") or "pass"
    if not port:
        return None
    import asyncio as _aio
    import subprocess

    def _run() -> Optional[str]:
        try:
            r = subprocess.run(
                ["curl", "--socks5-hostname", f"{user}:{passwd}@127.0.0.1:{port}",
                 "--max-time", "5", "http://api.ipify.org"],
                capture_output=True, text=True, timeout=8,
            )
            ip = r.stdout.strip()
            return ip if r.returncode == 0 and ip else None
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
    if not ip or ip in ("N/A", "1.1.1.1"):
        ip = None  # 需先查出口 IP
    if ip and node.get("exitCountry") and node.get("exitType") and node.get("exitRisk") is not None:
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
            # 无出口 IP → 经节点自身代理查询（探活已确认在线，代理应可达）
            if not cur_ip:
                fetched = await _fetch_exit_ip(node)
                if not fetched:
                    return
                cur_ip = fetched
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
            if len(_ip_enrich_last) > 5000:  # 防无限增长
                _ip_enrich_last.clear()

    asyncio.create_task(_do())

# 崩溃守护状态
_restart_times: List[float] = []
_guard_paused = False


# ---------- 探活 ----------

# 连续失败自动处理阈值
# 连续失败自动处理阈值（调保守：测活弱判定 + http:// testUrl 置空 bug 曾导致大量误杀）
DISABLE_AFTER_FAILS = 8   # 连续失败 ≥8 次 → 自动停用（探活误判率高，需更高阈值才停）
DELETE_AFTER_FAILS = 20   # 连续失败 ≥20 次 → 自动删除（释放端口；保守防止误删）
PROBE_CONCURRENCY = 24    # 探活并发上限（176 全并发会瞬时打满网络/触发风控，限流）

async def probe_nodes(ids: Optional[List[str]] = None, all_: bool = True,
                      include_disabled: bool = False) -> List[Dict[str, Any]]:
    """对节点经 clash API 并发探活。返回 {id, tag, ping, status, error}。

    失败计数：连续失败 DISABLE_AFTER_FAILS 次自动停用（status=disabled），
    达到 DELETE_AFTER_FAILS 次自动删除节点并重建配置；成功即清零。

    include_disabled=True（手动测活停用节点）时：临时启用 disabled 节点（生成
    outbound）→ 探活 → 失败恢复 disabled，通过则保持在线。
    """
    import config_manager as cm

    if not cm.is_running():
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
        try:
            async with __import__("httpx").AsyncClient(timeout=4.0) as client:
                r = await client.get(
                    f"{cm.clash_base()}/proxies/{tag}/delay",
                    params={"url": url, "timeout": "3000"},
                    headers={"Authorization": f"Bearer {cm.get_clash_secret()}"},
                )
            if r.status_code == 200 and r.json().get("delay"):
                # clash delay 只证明 TCP/TLS 握手能过（HEAD 不校验状态码，握手成功≠可用）。
                # 已有出口 IP 的节点：delay 足够（前轮已全链路验证过）。首次/无 IP 节点：
                # 追加真实出口链路验证（经 inbound curl 真实请求），能拿非空 IP 才判在线，
                # 否则降级为离线——避免"握手通但实际不可用"的假在线。
                cur_ip = node.get("exitIp")
                if cur_ip and cur_ip not in ("N/A", "1.1.1.1"):
                    return {"id": node["id"], "tag": tag, "ping": r.json().get("delay"),
                            "status": "online"}
                fetched = await _fetch_exit_ip(node)
                if not fetched:
                    return {"id": node["id"], "tag": tag, "ping": 0, "status": "offline",
                            "error": "握手成功但出口链路不可用"}
                return {"id": node["id"], "tag": tag, "ping": r.json().get("delay"),
                        "status": "online", "exitIp": fetched}
            msg = None
            try:
                msg = r.json().get("message")
            except Exception:
                pass
            return {"id": node["id"], "tag": tag, "ping": 0, "status": "offline",
                    "error": msg or f"HTTP {r.status_code}"}
        except Exception as e:
            return {"id": node["id"], "tag": tag, "ping": 0, "status": "offline", "error": str(e)}

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
            if res.get("exitIp"):
                db.update_node(nid, {"exitIp": res["exitIp"]})
                node["exitIp"] = res["exitIp"]
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
                await probe_nodes()
            except Exception:
                pass


# ---------- 订阅刷新 ----------

async def _sub_refresh_loop() -> None:
    while True:
        await asyncio.sleep(SUB_REFRESH_INTERVAL)
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
