"""clash_api 采集与流量统计。

- /traffic 流式数据 → 全局实时速率（up/down 本身就是速率，不做差分）
- /connections 5s 采样 → per-node 增量累计与窗口速率（relay 和真实出口分别归属）
- 维护每客户端 SSE 队列广播

注意：sing-box 未运行时所有采集静默降级，不报错。
"""
import asyncio
import json
import time
from typing import Any, Dict, List, Optional

import httpx

import config_manager
import db

_global_up_rate = 0.0
_global_down_rate = 0.0
_SAMPLE_INTERVAL = 5.0
_conn_sample_ts: Optional[float] = None

# per-node 归属；连接基线不随 tag 映射刷新清空，避免存量连接被全量重复累计。
_conn_state: Dict[str, Dict[str, Any]] = {}  # conn_id -> {up, down, tag, node_id}
_tag_to_node: Dict[str, str] = {}  # out tag -> node id
_relay_tags: set = set()
_node_rate: Dict[str, Dict[str, float]] = {}  # node_id -> {up, down, ts}
_relay_rate: Dict[str, Dict[str, float]] = {}  # relay tag -> {up, down, ts}
_relay_now_cache: Dict[str, str] = {}  # relay-auto-tag -> current leaf tag

_clients: List["asyncio.Queue"] = []
_traffic_task: Optional[asyncio.Task] = None
_conn_task: Optional[asyncio.Task] = None
_tag_map_refresh_task: Optional[asyncio.Task] = None
_broadcast_task: Optional[asyncio.Task] = None


def _clash_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {config_manager.get_clash_secret()}"}


async def _is_running() -> bool:
    """在线程池查询进程/API 状态，避免同步 fallback 探测阻塞事件循环。"""
    return await asyncio.to_thread(config_manager.is_running)


def _refresh_tag_maps() -> None:
    """重建 outbound tag → node id 映射（节点增删/端口变更后由 scheduler 周期调用）。
    同时清理 _node_rate / _relay_rate 中已删除节点/域名的条目防内存泄漏。"""
    global _tag_to_node, _relay_tags
    _tag_to_node = {}
    valid_node_ids = set()
    for n in db.list_nodes():
        _tag_to_node[config_manager.outbound_tag(n["protocol"], n["port"])] = n["id"]
        valid_node_ids.add(n["id"])
    for nid in list(_node_rate):
        if nid not in valid_node_ids:
            del _node_rate[nid]
    _relay_tags = {f"relay-auto-{rd['id']}" for rd in db.list_relay_domains()}
    for rates in (_relay_rate, _relay_now_cache):
        for tag in list(rates):
            if tag not in _relay_tags:
                del rates[tag]


async def _tag_map_refresh_loop() -> None:
    """每 15s 刷新 tag→node 映射，保证节点增删/端口变更后流量归属立即生效。"""
    while True:
        await asyncio.sleep(15)
        try:
            _refresh_tag_maps()
        except Exception:
            pass


def _resolve_leaf_tag(chains: List[str]) -> Optional[str]:
    """从连接 chains 里找叶子 outbound tag。
    优先 out-<proto>-<port>；若叶子是 relay-auto-<id>，用 urltest now 兜底。"""
    # chains 的顺序随实现不同；真实出口优先于 selector 的当前 now。
    for tag in reversed(chains):
        if tag.startswith("out-"):
            return tag
    for tag in reversed(chains):
        if tag.startswith("relay-auto-"):
            now = _relay_now_cache.get(tag)
            if now and now.startswith("out-"):
                return now
    return None


async def _update_relay_now() -> None:
    """刷新 urltest 当前选中出口（relay 流量归属兜底）。"""
    try:
        async with httpx.AsyncClient(timeout=2.0, trust_env=False) as client:
            # P2-10：先清掉已删除 relay 的残留缓存（防泄漏），再刷新现存 relay
            cur_tags = set()
            for rd in db.list_relay_domains():
                tag = f"relay-auto-{rd['id']}"
                cur_tags.add(tag)
                r = await client.get(f"{config_manager.clash_base()}/proxies/{tag}",
                                     headers=_clash_headers())
                if r.status_code == 200:
                    data = r.json()
                    if data.get("now"):
                        _relay_now_cache[tag] = data["now"]
            for stale in [k for k in _relay_now_cache if k not in cur_tags]:
                _relay_now_cache.pop(stale, None)
    except Exception:
        pass


# ---------- /traffic reader（全局速率） ----------

async def _traffic_reader() -> None:
    global _global_up_rate, _global_down_rate
    while True:
        if not await _is_running():
            _global_up_rate = _global_down_rate = 0.0
            await asyncio.sleep(2)
            continue
        try:
            async with httpx.AsyncClient(timeout=None, trust_env=False) as client:
                async with client.stream("GET", f"{config_manager.clash_base()}/traffic",
                                         headers=_clash_headers()) as resp:
                    if resp.status_code == 200:
                        async for raw in resp.aiter_lines():
                            if not raw.strip():
                                continue
                            try:
                                data = json.loads(raw)
                                up = max(0, int(data.get("up", 0)))
                                down = max(0, int(data.get("down", 0)))
                            except (ValueError, TypeError, AttributeError):
                                continue
                            _global_up_rate, _global_down_rate = up, down
        except (httpx.HTTPError, OSError):
            pass
        # 流结束/失败时清速率并退避，避免保留最后一帧或紧密重连。
        _global_up_rate = _global_down_rate = 0.0
        await asyncio.sleep(2)


# ---------- /connections 采样（per-node 归属） ----------

async def _connections_sampler() -> None:
    while True:
        if not await _is_running():
            await asyncio.sleep(2)
            continue
        try:
            await _update_relay_now()
            async with httpx.AsyncClient(timeout=3.0, trust_env=False) as client:
                r = await client.get(f"{config_manager.clash_base()}/connections",
                                     headers=_clash_headers())
                r.raise_for_status()
                data = r.json()
                conns = data.get("connections")
                if not isinstance(conns, list):
                    raise ValueError("invalid connections snapshot")
            _process_connections(conns)
        except Exception:
            # 请求/解析/写库失败不能冒充空快照，否则下次首见会全量重复累计。
            pass
        await asyncio.sleep(_SAMPLE_INTERVAL)


def _process_connections(conns: List[Dict[str, Any]]) -> None:
    global _conn_state, _conn_sample_ts, _node_rate, _relay_rate
    now = time.monotonic()
    dt = now - _conn_sample_ts if _conn_sample_ts is not None else _SAMPLE_INTERVAL
    if dt <= 0:
        dt = _SAMPLE_INTERVAL
    node_deltas: Dict[str, tuple[int, int]] = {}
    relay_deltas: Dict[str, tuple[int, int]] = {}
    next_state = {}
    for c in conns:
        cid = c.get("id")
        if not cid or cid in next_state:
            continue
        up = max(0, int(c.get("upload", 0)))
        down = max(0, int(c.get("download", 0)))
        chains = c.get("chains") or []
        prev = _conn_state.get(cid)
        # 已建立连接的出口不会随 selector now 的轮询切换；保留已知真实叶子。
        leaf = (prev and prev["tag"]) or _resolve_leaf_tag(chains)
        node_id = _tag_to_node.get(leaf)
        if prev and prev.get("node_id") and node_id != prev["node_id"]:
            # 删除节点/复用端口后，不把旧连接字节记到新节点。
            node_id = None
        dup = up if prev is None or up < prev["up"] else up - prev["up"]
        ddown = down if prev is None or down < prev["down"] else down - prev["down"]
        next_state[cid] = {"up": up, "down": down, "tag": leaf,
                           "node_id": prev.get("node_id") if prev and prev.get("node_id") else node_id}
        if dup == 0 and ddown == 0:
            continue
        if node_id:
            old_up, old_down = node_deltas.get(node_id, (0, 0))
            node_deltas[node_id] = (old_up + dup, old_down + ddown)
        # relay 标签与真实 leaf 是两种统计维度，不互斥；同链重复标签只记一次。
        for tag in set(chains) & _relay_tags:
            old_up, old_down = relay_deltas.get(tag, (0, 0))
            relay_deltas[tag] = (old_up + dup, old_down + ddown)
    if node_deltas:
        db.add_traffic_batch(node_deltas)
    # 先按节点聚合再除一次采样周期；不叠加上一窗口，避免恒定流量速率虚增。
    _node_rate = {nid: {"up": up / dt, "down": down / dt, "ts": now}
                  for nid, (up, down) in node_deltas.items()}
    _relay_rate = {tag: {"up": up / dt, "down": down / dt, "ts": now}
                   for tag, (up, down) in relay_deltas.items()}
    _conn_state = next_state
    _conn_sample_ts = now


# ---------- 对外查询 ----------

def get_stats() -> Dict[str, Any]:
    nodes = db.list_nodes()
    now = time.monotonic()
    node_stats = []
    for n in nodes:
        rate = _node_rate.get(n["id"], {"up": 0.0, "down": 0.0, "ts": 0})
        # 速率衰减：自上次 delta 起按 5s 半衰期衰减，无流量时趋近 0
        age = max(0, now - rate.get("ts", 0))
        decay = 0.5 ** (age / 5.0)
        up_rate = rate["up"] * decay
        down_rate = rate["down"] * decay
        node_stats.append({
            "id": n["id"], "port": n["port"],
            "upTraffic": n["upTraffic"], "downTraffic": n["downTraffic"],
            "upRate": up_rate, "downRate": down_rate,
            "status": n["status"], "ping": n["ping"],
        })
    relay_stats = []
    for rd in db.list_relay_domains():
        r = _relay_rate.get(f"relay-auto-{rd['id']}", {"up": 0.0, "down": 0.0, "ts": 0})
        age = max(0, now - r.get("ts", 0))
        decay = 0.5 ** (age / 5.0)
        relay_stats.append({"id": rd["id"], "port": rd["port"],
                            "upRate": r["up"] * decay, "downRate": r["down"] * decay})
    return {
        "global": {
            "upRate": _global_up_rate, "downRate": _global_down_rate,
            "upTotal": sum(n["upTraffic"] for n in nodes),
            "downTotal": sum(n["downTraffic"] for n in nodes),
        },
        "activeConnections": len(_conn_state),
        "nodes": node_stats,
        "relayDomains": relay_stats,
    }


def subscribe_sse() -> "asyncio.Queue":
    q: asyncio.Queue = asyncio.Queue(maxsize=100)
    _clients.append(q)
    return q


def unsubscribe_sse(q: "asyncio.Queue") -> None:
    if q in _clients:
        _clients.remove(q)


async def _broadcast() -> None:
    """每 1s 广播一次 stats 快照到所有 SSE 客户端。"""
    _full_count: Dict[int, int] = {}  # queue id → 连续满次数
    while True:
        await asyncio.sleep(1)
        if not _clients:
            continue
        snapshot = get_stats()
        payload = json.dumps({
            "type": "traffic",
            "time": time.time(),
            "up": snapshot["global"]["upRate"],
            "down": snapshot["global"]["downRate"],
            "upRate": snapshot["global"]["upRate"],
            "downRate": snapshot["global"]["downRate"],
            "activeConnections": snapshot["activeConnections"],
            "nodes": snapshot["nodes"],
            "relayDomains": snapshot["relayDomains"],
        }, ensure_ascii=False)
        for q in list(_clients):
            try:
                q.put_nowait(payload)
                _full_count.pop(id(q), None)
            except asyncio.QueueFull:
                # H3 fix：连续满 60 次（约 60s）的客户端视为断连泄漏，清理
                cnt = _full_count.get(id(q), 0) + 1
                _full_count[id(q)] = cnt
                if cnt >= 60:
                    _clients.remove(q)
                    _full_count.pop(id(q), None)


# ---------- 生命周期 ----------

def start_tasks(loop: asyncio.AbstractEventLoop) -> None:
    global _traffic_task, _conn_task, _tag_map_refresh_task, _broadcast_task
    if any(t and not t.done() for t in
           (_traffic_task, _conn_task, _tag_map_refresh_task, _broadcast_task)):
        return
    _refresh_tag_maps()
    _traffic_task = loop.create_task(_traffic_reader())
    _conn_task = loop.create_task(_connections_sampler())
    _tag_map_refresh_task = loop.create_task(_tag_map_refresh_loop())
    _broadcast_task = loop.create_task(_broadcast())


async def stop_tasks() -> None:
    global _traffic_task, _conn_task, _tag_map_refresh_task, _broadcast_task
    global _global_up_rate, _global_down_rate
    tasks = [t for t in (_traffic_task, _conn_task, _tag_map_refresh_task, _broadcast_task) if t]
    for task in tasks:
        task.cancel()
    if tasks:
        await asyncio.gather(*tasks, return_exceptions=True)
    _traffic_task = _conn_task = _tag_map_refresh_task = _broadcast_task = None
    _global_up_rate = _global_down_rate = 0.0
