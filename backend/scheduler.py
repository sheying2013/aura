"""后台任务编排：60s 批量探活、6h 订阅刷新、10s sing-box 崩溃守护。"""
import asyncio
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

# 崩溃守护状态
_restart_times: List[float] = []
_guard_paused = False


# ---------- 探活 ----------

# 连续失败自动处理阈值
DISABLE_AFTER_FAILS = 5   # 连续失败 ≥5 次 → 自动停用（不参与轮询/探活）
DELETE_AFTER_FAILS = 10   # 连续失败 ≥10 次 → 自动删除（释放端口）

async def probe_nodes(ids: Optional[List[str]] = None, all_: bool = True) -> List[Dict[str, Any]]:
    """对节点经 clash API 并发探活。返回 {id, tag, ping, status, error}。

    失败计数：连续失败 DISABLE_AFTER_FAILS 次自动停用（status=disabled），
    达到 DELETE_AFTER_FAILS 次自动删除节点并重建配置；成功即清零。
    """
    import config_manager as cm

    if not cm.is_running():
        return []
    nodes = db.list_nodes()
    if not all_ and ids:
        nodes = [n for n in nodes if n["id"] in ids]
    # 已停用的节点跳过探活（前端可手动重新启用）
    nodes = [n for n in nodes if n.get("status") != "disabled"]

    async def _probe_one(node: Dict[str, Any]) -> Dict[str, Any]:
        tag = cm.outbound_tag(node["protocol"], node["port"])
        url = (db.get_setting("system", {}) or {}).get("testUrl", "https://www.gstatic.com/generate_204")
        try:
            async with __import__("httpx").AsyncClient(timeout=4.0) as client:
                r = await client.get(
                    f"{cm.clash_base()}/proxies/{tag}/delay",
                    params={"url": url, "timeout": "3000"},
                    headers={"Authorization": f"Bearer {cm.get_clash_secret()}"},
                )
            if r.status_code == 200:
                delay = r.json().get("delay")
                return {"id": node["id"], "tag": tag, "ping": delay, "status": "online"}
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
    results = await asyncio.gather(*(_probe_one(n) for n in nodes))
    # 结果落库 + 失败计数 → 自动停用/删除（_probe_one 不落库，避免双重计数）
    for node, res in zip(nodes, results):
        if res.get("status") == "online":
            db.update_node_probe(node["id"], res.get("ping", 0), "online")  # 成功清零
            continue
        fails = db.update_node_probe(node["id"], 0, "offline")  # 失败 +1 并返回累计值
        if fails >= DELETE_AFTER_FAILS:
            print(f"[probe] 节点 [{node.get('name')}] 连续失败 {fails} 次，自动删除")
            db.delete_node(node["id"])
            try:
                await cm.apply_config()
            except Exception:
                pass
        elif fails >= DISABLE_AFTER_FAILS:
            print(f"[probe] 节点 [{node.get('name')}] 连续失败 {fails} 次，自动停用")
            db.update_node(node["id"], {"status": "disabled"})
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
    loop.create_task(_guard_loop())
