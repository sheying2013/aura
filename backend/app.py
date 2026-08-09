"""FastAPI 入口：路由注册、CORS、静态挂载、lifespan（建库 + 拉起 sing-box + 启动后台任务）。

面板入口：http://<host>:19001/admin
"""
import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles

import auth
import config_manager
import db
import models
import panel_config
import scheduler
import stats
import subs_proxy

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
STATIC_DIR = os.path.join(BASE_DIR, "static")
DATA_DIR = os.path.join(BASE_DIR, "data")
# 面板路径前缀（默认 /admin，可用 aura CLI / panel.conf 修改）
PANEL_PATH = panel_config.get("panel_path") or "/admin"


def _client_ip(request: Request) -> str:
    # 取真实客户端 IP（支持反向代理 X-Forwarded-For）
    xff = request.headers.get("x-forwarded-for", "")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else ""


def require_auth(request: Request) -> None:
    """所有 /api 请求必须带有效 Bearer token。AUTH_DISABLED=1 时跳过（本地调试用）。"""
    if os.environ.get("AUTH_DISABLED") == "1":
        return
    auth_header = request.headers.get("authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="未登录或登录已过期")
    token = auth_header[len("Bearer "):].strip()
    if not auth.verify_token(token):
        raise HTTPException(status_code=401, detail="未登录或登录已过期")


@asynccontextmanager
async def lifespan(app: FastAPI):
    os.makedirs(DATA_DIR, exist_ok=True)
    os.makedirs(STATIC_DIR, exist_ok=True)
    db.init_db()
    # 拉起 sing-box（若已有配置）
    if os.path.exists(config_manager.CONFIG_PATH) or os.path.exists(config_manager.CONFIG_BAK_PATH):
        await config_manager.start()
    # 后台任务
    scheduler.start_scheduler(asyncio.get_event_loop())
    stats.start_tasks(asyncio.get_event_loop())
    yield
    # 关停
    stats.stop_tasks()
    await config_manager.stop()


app = FastAPI(title="SingBox 中转枢纽", lifespan=lifespan)

@app.get("/api/auth/status", dependencies=[Depends(require_auth)])
def auth_status():
    auth_disabled = os.environ.get("AUTH_DISABLED") == "1"
    return {
        "authenticated": True,
        "username": auth.get_username(),
        "passwordChangeRequired": False if auth_disabled else auth.is_password_change_required(),
    }


@app.post("/api/auth/login")
async def auth_login(body: dict, request: Request):
    username = body.get("username", "")
    password = body.get("password", "")
    result = await auth.login(username, password, _client_ip(request))
    if not result["ok"]:
        raise HTTPException(status_code=401, detail=result["error"])
    return result


@app.post("/api/auth/logout", dependencies=[Depends(require_auth)])
def auth_logout(request: Request):
    token = request.headers.get("authorization", "")[len("Bearer "):].strip()
    auth.logout_token(token)
    return {"ok": True}


@app.post("/api/auth/change-password", dependencies=[Depends(require_auth)])
def auth_change_password(body: dict):
    old_password = body.get("oldPassword", "")
    new_password = body.get("newPassword", "")
    result = auth.change_password(old_password, new_password)
    if not result["ok"]:
        raise HTTPException(status_code=400, detail=result["error"])
    return result


@app.get("/api/auth/check", dependencies=[Depends(require_auth)])
def auth_check():
    return {"ok": True}

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------- 节点 CRUD ----------

@app.get("/api/nodes", response_model=models.NodeListResponse, dependencies=[Depends(require_auth)])
def list_nodes(q: Optional[str] = None, group: Optional[str] = None, subId: Optional[str] = None):
    items = db.list_nodes(q=q, group=group, sub_id=subId)
    return {"items": items, "total": len(items)}


@app.post("/api/nodes", response_model=models.Node, status_code=201, dependencies=[Depends(require_auth)])
def create_node(body: models.NodeCreate):
    port = body.port
    if not port:
        port = db.get_next_available_port(None)
    # 冲突检查：nodes + relay_domains + reservedPorts 全查
    used_ports = set(n["port"] for n in db.list_nodes())
    used_ports |= set(rd["port"] for rd in db.list_relay_domains())
    used_ports |= set(int(p) for p in (db.get_setting("system", {}).get("reservedPorts", []) or []))
    if port in used_ports:
        raise HTTPException(status_code=409, detail={"port": port, "reason": "端口已被占用（节点/域名/保留段）"})
    node = {
        "id": db.new_node_id(),
        "name": body.name,
        "protocol": body.protocol,
        "group": body.group or "默认分组",
        "port": port,
        "segment": None,
        "authUser": body.authUser,
        "authPass": body.authPass,
        "status": body.status or "offline",
        "ping": body.ping or 0,
        "exitIp": body.exitIp or "N/A",
        "upTraffic": body.upTraffic or 0,
        "downTraffic": body.downTraffic or 0,
        "rawConfig": body.rawConfig or {},
        "subId": body.subId,
        "subName": body.subName,
        "stale": False,
        "selected": False,
        "entryProto": body.entryProto or "mixed",
        "ssPass": body.ssPass,
    }
    return db.create_node(node)


@app.post("/api/nodes/batch", response_model=models.NodeBatchResponse, dependencies=[Depends(require_auth)])
def create_node_batch(body: models.NodeBatchRequest):
    prepared = []
    for n in body.nodes:
        prepared.append({
            "id": db.new_node_id(),
            "name": n.name,
            "protocol": n.protocol,
            "group": n.group or "默认分组",
            # port 交给 db.create_node_batch 批内自动分配（52001 起自增，避免批内冲突）
            "port": n.port,
            "segment": None,
            "authUser": n.authUser,
            "authPass": n.authPass,
            "status": n.status or "offline",
            "ping": n.ping or 0,
            "exitIp": n.exitIp or "N/A",
            "upTraffic": n.upTraffic or 0,
            "downTraffic": n.downTraffic or 0,
            "rawConfig": n.rawConfig or {},
            "subId": n.subId,
            "subName": n.subName,
            "stale": False,
            "selected": False,
            "entryProto": n.entryProto or "mixed",
            "ssPass": n.ssPass,
        })
    return db.create_node_batch(prepared)


@app.patch("/api/nodes/{node_id}", response_model=models.Node, dependencies=[Depends(require_auth)])
def patch_node(node_id: str, body: models.NodePatch):
    # exclude_unset=True 只取用户实际传的字段，允许显式传 None 清空可选字段
    patch = {k: v for k, v in body.model_dump(exclude_unset=True).items()}
    node = db.update_node(node_id, patch)
    if not node:
        raise HTTPException(status_code=404, detail="节点不存在")
    return node


@app.put("/api/nodes/{node_id}/port", response_model=models.Node, dependencies=[Depends(require_auth)])
def update_node_port(node_id: str, body: models.PortUpdateRequest):
    node = db.update_node_port(node_id, body.port)
    if not node:
        raise HTTPException(status_code=404, detail="节点不存在")
    return node


@app.post("/api/nodes/convert-entry", response_model=models.EntryConvertResponse, dependencies=[Depends(require_auth)])
async def convert_node_entry(body: models.EntryConvertRequest):
    """批量切换节点对外入口协议：mixed（socks5+http）↔ ss（Shadowsocks aes-256-gcm）。

    - 转 ss：ssPass 可统一指定，空则每个节点随机生成
    - 转回 mixed：恢复原 authUser/authPass 认证
    转换后自动重载 sing-box 配置使新入口生效。
    """
    if body.entryProto not in ("mixed", "ss"):
        raise HTTPException(status_code=400, detail="entryProto 仅支持 mixed | ss")

    converted, failed, errors = 0, 0, []
    items = []
    ids = body.ids or [n["id"] for n in db.list_nodes()]
    for node_id in ids:
        node = db.get_node(node_id)
        if not node:
            failed += 1
            errors.append({"node": node_id, "reason": "节点不存在"})
            continue
        if body.entryProto == node.get("entryProto"):
            items.append(node)
            continue
        new_proto = body.entryProto
        updated = db.update_node_entry(node_id, new_proto, body.ssPass)
        if not updated:
            failed += 1
            errors.append({"node": node.get("name", node_id), "reason": "更新失败"})
            continue
        items.append(updated)
        converted += 1

    # 热重载 sing-box 使新入口生效（失败不阻断返回，配置保留待下次 apply）
    try:
        await config_manager.apply_config()
    except Exception:
        pass

    return {"ok": True, "converted": converted, "failed": failed, "errors": errors, "items": items}


@app.delete("/api/nodes/{node_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_node(node_id: str):
    if not db.delete_node(node_id):
        raise HTTPException(status_code=404, detail="节点不存在")


@app.post("/api/nodes/delete-batch", response_model=models.DeleteBatchResponse, dependencies=[Depends(require_auth)])
def delete_node_batch(body: models.DeleteBatchRequest):
    if not body.ids:
        raise HTTPException(status_code=400, detail="ids 不能为空")
    return {"deleted": db.delete_node_batch(body.ids)}


@app.post("/api/groups/rename", dependencies=[Depends(require_auth)])
async def rename_group(body: dict):
    """分组重命名：批量更新节点分组 + relay 域名引用，重命名后重建配置。"""
    old_name = (body.get("oldName") or "").strip()
    new_name = (body.get("newName") or "").strip()
    if not old_name or not new_name:
        raise HTTPException(status_code=400, detail="oldName/newName 不能为空")
    result = db.rename_group(old_name, new_name)
    if result["updated"] == 0 and result["relayUpdated"] == 0:
        raise HTTPException(status_code=404, detail=f"分组 [{old_name}] 不存在")
    # 分组名变更影响 relay 池 → 重建配置
    try:
        await config_manager.apply_config()
    except Exception:
        pass
    return {"ok": True, **result}


@app.post("/api/nodes/{node_id}/traffic/reset", response_model=models.Node, dependencies=[Depends(require_auth)])
def reset_node_traffic(node_id: str):
    node = db.reset_node_traffic(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="节点不存在")
    return node


@app.post("/api/traffic/reset", dependencies=[Depends(require_auth)])
def reset_all_traffic():
    db.reset_all_traffic()
    return {"ok": True}


# ---------- 探活 ----------

@app.post("/api/nodes/ping", response_model=List[models.PingResultItem], dependencies=[Depends(require_auth)])
async def ping_nodes(body: models.PingRequest):
    return await scheduler.probe_nodes(ids=body.ids, all_=body.all,
                                       include_disabled=body.includeDisabled)


@app.get("/api/nodes/{node_id}/exit-ip", dependencies=[Depends(require_auth)])
async def get_exit_ip(node_id: str):
    node = db.get_node(node_id)
    if not node:
        raise HTTPException(status_code=404, detail="节点不存在")
    if not config_manager.is_running():
        raise HTTPException(status_code=409, detail="sing-box 未运行")
    port = node["port"]
    user = node.get("authUser") or "user"
    passwd = node.get("authPass") or "pass"
    ip = await scheduler._fetch_exit_ip(node)
    if not ip:
        raise HTTPException(status_code=502, detail="出口 IP 探测失败")
    patch = {"exitIp": ip}
    # 异步查 IP 情报（ipinfo.io 归属地 + ipapi.is 纯净度评分），失败降级不阻塞
    try:
        import ipinfo
        info = await asyncio.to_thread(ipinfo.lookup, ip)
        for k in ("exitCountry", "exitFlag", "exitCity", "exitType", "exitScore"):
            if k in info:
                patch[k] = info[k]
    except Exception:
        pass
    db.update_node(node_id, patch)
    node = db.get_node(node_id)
    return {"exitIp": ip, "ping": node.get("ping"), **{k: patch.get(k) for k in
            ("exitCountry", "exitFlag", "exitCity", "exitType", "exitScore") if k in patch}}


# ---------- sing-box 配置 ----------

@app.get("/api/config", dependencies=[Depends(require_auth)])
def get_config():
    built = config_manager.build_config()
    return {
        "config": built["config"],
        "errors": built["errors"],
        "applied": os.path.exists(config_manager.CONFIG_PATH),
        "singboxRunning": config_manager.is_running(),
        "generatedAt": int(time.time() * 1000),
    }


@app.post("/api/config/apply", response_model=models.ConfigApplyResponse, dependencies=[Depends(require_auth)])
async def apply_config(body: Optional[dict] = None):
    if body and body.get("config"):
        return await config_manager.apply_config(body["config"])
    return await config_manager.apply_config()


@app.get("/api/config/status", response_model=models.ConfigStatus, dependencies=[Depends(require_auth)])
async def config_status():
    return await config_manager.status()


@app.post("/api/config/start", dependencies=[Depends(require_auth)])
async def config_start():
    ok = await config_manager.start()
    return {"running": ok}


@app.post("/api/config/stop", dependencies=[Depends(require_auth)])
async def config_stop():
    await config_manager.stop()
    return {"running": False}


@app.post("/api/config/restart", dependencies=[Depends(require_auth)])
async def config_restart():
    await config_manager.stop()
    await asyncio.sleep(0.5)
    ok = await config_manager.start()
    return {"running": ok}


# ---------- 订阅 ----------

@app.get("/api/subs", response_model=List[models.Subscription], dependencies=[Depends(require_auth)])
def list_subs():
    return db.list_subs()


@app.post("/api/subs", response_model=models.Subscription, status_code=201, dependencies=[Depends(require_auth)])
def create_sub(body: models.SubCreate):
    sub = db.create_sub(body.url, body.name, body.group)
    if not sub:
        raise HTTPException(status_code=409, detail="订阅 URL 已存在")
    return sub


@app.delete("/api/subs/{sub_id}", status_code=204, dependencies=[Depends(require_auth)])
def delete_sub(sub_id: str):
    if not db.delete_sub(sub_id):
        raise HTTPException(status_code=404, detail="订阅不存在")


@app.post("/api/subs/{sub_id}/toggle", response_model=models.Subscription, dependencies=[Depends(require_auth)])
def toggle_sub(sub_id: str, body: models.SubToggleRequest):
    sub = db.update_sub(sub_id, {"enabled": body.enabled})
    if not sub:
        raise HTTPException(status_code=404, detail="订阅不存在")
    return sub


@app.post("/api/subs/fetch", response_model=models.SubFetchResponse, dependencies=[Depends(require_auth)])
async def sub_fetch(body: models.SubFetchRequest):
    return await subs_proxy.fetch_subscription(body.url)


@app.post("/api/subs/refresh", response_model=models.SubRefreshResponse, dependencies=[Depends(require_auth)])
async def sub_refresh(body: models.SubRefreshRequest):
    results = await subs_proxy.refresh_subs(ids=body.ids, all_=body.all)
    return {"results": results}


@app.post("/api/subs/parse", response_model=models.SubParseResponse, dependencies=[Depends(require_auth)])
def sub_parse(body: models.SubParseRequest):
    nodes = subs_proxy.parse_content(body.content)
    return {"nodes": nodes}


# ---------- 流量统计 ----------

@app.get("/api/stats", response_model=models.StatsResponse, dependencies=[Depends(require_auth)])
def get_stats():
    return stats.get_stats()


@app.get("/api/stats/stream", dependencies=[Depends(require_auth)])
async def stats_stream():
    q = stats.subscribe_sse()

    async def gen():
        try:
            while True:
                payload = await q.get()
                yield f"data: {payload}\n\n"
        finally:
            stats.unsubscribe_sse(q)

    return StreamingResponse(gen(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/stats/connections", dependencies=[Depends(require_auth)])
async def stats_connections():
    if not config_manager.is_running():
        return {"connections": []}
    import httpx
    try:
        async with httpx.AsyncClient(timeout=3.0) as client:
            r = await client.get(f"{config_manager.clash_base()}/connections",
                                 headers={"Authorization": f"Bearer {config_manager.get_clash_secret()}"})
            return r.json()
    except Exception:
        return {"connections": []}


# ---------- 面板设置 ----------

@app.get("/api/settings", dependencies=[Depends(require_auth)])
def get_settings():
    return db.get_setting("system", {})


@app.put("/api/settings", dependencies=[Depends(require_auth)])
async def put_settings(body: dict):
    # testUrl 校验：sing-box clash API 对 http:// url 置空并回退 gstatic，探活测的不是
    # 配置的 URL → 强制 https://（否则所有节点探活失真，曾导致大量误停用）
    if body.get("testUrl"):
        tu = str(body["testUrl"])
        if tu.startswith("http://"):
            body["testUrl"] = tu.replace("http://", "https://", 1)
    db.set_setting("system", body)
    # 同步 relay_domains 表（供后端查询用）
    if isinstance(body.get("relayDomains"), list):
        db.upsert_relay_domains(body["relayDomains"])
    # 设置/域名变更后自动重生成并热重载 sing-box（新域名入口立即生效）
    try:
        await config_manager.apply_config()
    except Exception:
        pass
    return {"ok": True}


# ---------- 静态挂载（面板路径前缀 /admin） ----------

@app.get("/", include_in_schema=False)
async def root_redirect():
    return RedirectResponse(url=PANEL_PATH + "/")


@app.get(PANEL_PATH, include_in_schema=False)
async def panel_redirect():
    return RedirectResponse(url=PANEL_PATH + "/")


# 静态文件挂到 /admin 前缀；/admin 下 html=True 自动出 index.html
app.mount(PANEL_PATH, StaticFiles(directory=STATIC_DIR, html=True), name="static")

