"""clash_api 采集与流量统计。

- /traffic SSE 差分 → 全局实时速率（sing-box 重启检测计数器回退）
- /connections 5s 采样 → per-node 归属增量累计（chains 找 out-* 叶子；relay-auto 用 urltest now 兜底）
- 维护每客户端 SSE 队列广播

注意：sing-box 未运行时所有采集静默降级，不报错。
"""
import asyncio
import json
import re
import time
from typing import Any, Dict, List, Optional

import httpx

import config_manager
import db

_UP = 0
_DOWN = 0
_up_total = 0
_down_total = 0
_global_up_rate = 0.0
_global_down_rate = 0.0
_last_traffic_ts: Optional[float] = None
_last_up: Optional[int] = None
_last_down: Optional[int] = None

# per-node 归属
_conn_state: Dict[str, Dict[str, Any]] = {}  # conn_id -> {up, down, tag}
_tag_to_node: Dict[str, str] = {}  # out tag -> node id
_node_rate: Dict[str, Dict[str, float]] = {}  # node_id -> {up, down} (5s 窗口速率)
_relay_rate: Dict[str, Dict[str, float]] = {}  # relay tag -> {up, down}
_relay_now_cache: Dict[str, str] = {}  # relay-auto-tag -> current leaf tag

_clients: List["asyncio.Queue"] = []
_traffic_task: Optional[asyncio.Task] = None
_conn_task: Optional[asyncio.Task] = None


def _clash_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {config_manager.get_clash_secret()}"}


def _refresh_tag_maps() -> None:
    """重建 outbound tag → node id 映射（节点增删/端口变更后由 scheduler 周期调用）。"""
    global _tag_to_node
    _tag_to_node = {}
    for n in db.list_nodes():
        _tag_to_node[config_manager.outbound_tag(n["protocol"], n["port"])] = n["id"]


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
    if not chains:
        return None
    leaf = chains[-1]
    if re.match(r"^out-", leaf):
        return leaf
    if re.match(r"^relay-auto-", leaf):
        now = _relay_now_cache.get(leaf)
        if now and re.match(r"^out-", now):
            return now
    # 兜底：在整条链里找第一个 out-* tag
    for t in chains:
        if re.match(r"^out-", t):
            return t
    return None


async def _update_relay_now() -> None:
    """刷新 urltest 当前选中出口（relay 流量归属兜底）。"""
    try:
        async with httpx.AsyncClient(timeout=2.0) as client:
            for rd in db.list_relay_domains():
                tag = f"relay-auto-{rd['id']}"
                r = await client.get(f"{config_manager.clash_base()}/proxies/{tag}",
                                     headers=_clash_headers())
                if r.status_code == 200:
                    data = r.json()
                    if data.get("now"):
                        _relay_now_cache[tag] = data["now"]
    except Exception:
        pass


# ---------- /traffic reader（全局速率） ----------

async def _traffic_reader() -> None:
    global _up_total, _down_total, _global_up_rate, _global_down_rate
    global _last_traffic_ts, _last_up, _last_down
    while True:
        if not config_manager.is_running():
            await asyncio.sleep(2)
            continue
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", f"{config_manager.clash_base()}/traffic",
                                         headers=_clash_headers()) as resp:
                    if resp.status_code != 200:
                        await asyncio.sleep(2)
                        continue
                    async for raw in resp.aiter_lines():
                        if not raw.strip():
                            continue
                        try:
                            d = json.loads(raw)
                        except Exception:
                            continue
                        up, down = int(d.get("up", 0)), int(d.get("down", 0))
                        now = time.time()
                        # 重启检测：计数器回退
                        if _last_up is not None and (up < _last_up or down < _last_down):
                            _last_up, _last_down, _last_traffic_ts = None, None, None
                        if _last_up is not None and _last_traffic_ts is not None:
                            dt = now - _last_traffic_ts
                            if dt > 0:
                                _global_up_rate = max(0, up - _last_up) / dt
                                _global_down_rate = max(0, down - _last_down) / dt
                        _up_total, _down_total = up, down
                        _last_up, _last_down, _last_traffic_ts = up, down, now
        except Exception:
            await asyncio.sleep(2)


# ---------- /connections 采样（per-node 归属） ----------

async def _connections_sampler() -> None:
    global _conn_state
    while True:
        if not config_manager.is_running():
            await asyncio.sleep(2)
            continue
        try:
            await _update_relay_now()
            async with httpx.AsyncClient(timeout=3.0) as client:
                r = await client.get(f"{config_manager.clash_base()}/connections",
                                     headers=_clash_headers())
                if r.status_code != 200:
                    await asyncio.sleep(2)
                    continue
                data = r.json()
                conns = data.get("connections") or []
        except Exception:
            conns = []
        _process_connections(conns)
        await asyncio.sleep(5)


def _process_connections(conns: List[Dict[str, Any]]) -> None:
    global _conn_state
    now = time.time()
    seen = set()
    for c in conns:
        cid = c.get("id")
        if not cid:
            continue
        seen.add(cid)
        up = int(c.get("upload", 0))
        down = int(c.get("download", 0))
        chains = c.get("chains") or []
        leaf = _resolve_leaf_tag(chains)
        prev = _conn_state.get(cid)
        if prev is None:
            # 首次见到：只记基线，不归属（避免采样前字节）
            _conn_state[cid] = {"up": up, "down": down, "tag": leaf, "ts": now}
            continue
        dup = max(0, up - prev["up"])
        ddown = max(0, down - prev["down"])
        leaf = leaf or prev["tag"]
        dt = max(0.001, now - prev.get("ts", now))
        prev["up"], prev["down"], prev["tag"], prev["ts"] = up, down, leaf, now
        if (dup == 0 and ddown == 0) or not leaf:
            continue
        node_id = _tag_to_node.get(leaf)
        if node_id:
            db.add_traffic(node_id, dup, ddown)
            nr = _node_rate.setdefault(node_id, {"up": 0.0, "down": 0.0, "ts": now})
            nr["up"] += dup / dt
            nr["down"] += ddown / dt
            nr["ts"] = now
        elif leaf.startswith("relay-auto-"):
            rr = _relay_rate.setdefault(leaf, {"up": 0.0, "down": 0.0, "ts": now})
            rr["up"] += dup / dt
            rr["down"] += ddown / dt
            rr["ts"] = now
    # 清理消失连接
    for cid in [k for k in _conn_state if k not in seen]:
        del _conn_state[cid]


# ---------- 对外查询 ----------

def get_stats() -> Dict[str, Any]:
    nodes = db.list_nodes()
    now = time.time()
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
            "upTotal": _up_total, "downTotal": _down_total,
        },
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
            "nodes": snapshot["nodes"],
            "relayDomains": snapshot["relayDomains"],
        }, ensure_ascii=False)
        for q in list(_clients):
            try:
                q.put_nowait(payload)
            except asyncio.QueueFull:
                pass


# ---------- 生命周期 ----------

def start_tasks(loop: asyncio.AbstractEventLoop) -> None:
    global _traffic_task, _conn_task
    _refresh_tag_maps()
    _traffic_task = loop.create_task(_traffic_reader())
    _conn_task = loop.create_task(_connections_sampler())
    loop.create_task(_tag_map_refresh_loop())
    loop.create_task(_broadcast())


def stop_tasks() -> None:
    global _traffic_task, _conn_task
    for t in (_traffic_task, _conn_task):
        if t:
            t.cancel()
    _traffic_task = _conn_task = None
