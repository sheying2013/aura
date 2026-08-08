"""sing-box 配置生成与子进程托管。

- build_config(): 从 DB 数据生成 sing-box JSON（移植前端 generateSingboxConfig + clash_api 块 + 协议归一化）
- 校验（sing-box check）、原子写、SIGHUP 热重载、.bak 回滚
- 端口冲突检测、启动/停止/重启/状态

协议归一化：ss→shadowsocks；ssr→sing-box 1.6 起已移除，跳过并告警；其余透传。
"""
import asyncio
import json
import os
import random
import secrets
import signal
import socket
import subprocess
import time
from typing import Any, Dict, List, Optional, Set

import httpx

import db

SINGBOX_BIN = os.environ.get("SINGBOX_BIN", "sing-box")
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "data"))
CONFIG_PATH = os.path.join(DATA_DIR, "config.json")
CONFIG_BAK_PATH = os.path.join(DATA_DIR, "config.json.bak")
LOG_PATH = os.path.join(DATA_DIR, "singbox.log")
CLASH_HOST = "127.0.0.1"
# 不用 9090（与其他面板/服务冲突常见），选 9095 避开常见占用
CLASH_PORT = 9095

# 前端 protocol 值 → sing-box outbound type；None = 不支持（跳过）
PROTOCOL_TYPE_MAP: Dict[str, Optional[str]] = {
    "shadowsocks": "shadowsocks",
    "ss": "shadowsocks",
    "vmess": "vmess",
    "vless": "vless",
    "trojan": "trojan",
    "hysteria2": "hysteria2",
    "tuic": "tuic",
    "wireguard": "wireguard",
    "socks": "socks",
    "socks5": "socks",
    "http": "http",
    "https": "http",
    "ssr": None,  # sing-box >=1.6 已移除 ShadowsocksR
}


def _tls_enabled_dict(cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """类型安全地取 tls 配置。clash YAML 把 tls: true 存成字符串 'true'，
    JSON 可能存 bool，必须兼容。返回启用时的 tls dict，否则 None。"""
    tls = cfg.get("tls")
    if isinstance(tls, dict):
        return tls if tls.get("enabled") else None
    if isinstance(tls, str):
        return {"enabled": True} if tls.lower() == "true" else None
    if isinstance(tls, bool):
        return {"enabled": True} if tls else None
    return None

def _normalize_transport(tr: Any) -> Optional[Dict[str, Any]]:
    """transport 规范化：sing-box V2RayTransportOptions 必须是对象。

    老订阅节点 DB 里可能存字符串（如 "ws"），直接透传会让 check 失败
    （json: cannot unmarshal string into ... transport）。字符串 → {type: str}。
    """
    if isinstance(tr, dict):
        return tr if tr.get("type") else None
    if isinstance(tr, str) and tr:
        return {"type": tr}
    return None


# 进程状态
_proc: Optional[asyncio.subprocess.Process] = None
_started_at: Optional[float] = None
_last_good_config: Optional[Dict] = None  # 最近一次成功 apply 的配置（回滚参考）
_op_lock = asyncio.Lock()  # 串行化 apply/start/stop，避免 SIGHUP/SIGTERM 竞态
_logf = None  # sing-box 日志文件句柄，避免 fd 泄漏
_wait_task: Optional[asyncio.Task] = None  # 收割子进程的 wait() 任务


# ---------- clash secret ----------

def get_clash_secret() -> str:
    secret = db.get_setting("clash_secret")
    if not secret:
        secret = secrets.token_urlsafe(16)
        db.set_setting("clash_secret", secret)
    return secret


def clash_base() -> str:
    return f"http://{CLASH_HOST}:{CLASH_PORT}"


def outbound_tag(protocol: str, port: int) -> str:
    return f"out-{protocol}-{port}"


# ---------- 配置生成 ----------

def build_config() -> Dict[str, Any]:
    """从 DB 数据生成完整 sing-box 配置。返回 {config, errors}。"""
    nodes = db.list_nodes()
    relay_domains = db.list_relay_domains()
    settings = db.get_setting("system", {}) or {}
    listen_ip = settings.get("listenIp", "0.0.0.0")
    test_url = settings.get("testUrl", "https://www.gstatic.com/generate_204")

    inbounds: List[Dict] = []
    outbounds: List[Dict] = []
    route_rules: List[Dict] = []
    errors: List[Dict[str, str]] = []
    outbound_tag_set: Set[str] = set()

    for node in nodes:
        # 已停用节点（连续探活失败自动停用）：不生成 inbound/outbound，不参与轮询
        if node.get("status") == "disabled":
            continue
        sb_type = PROTOCOL_TYPE_MAP.get(node["protocol"])
        if sb_type is None:
            errors.append({"node": node["name"], "reason": f"协议 {node['protocol']} 不被 sing-box 1.7 支持，已跳过"})
            continue
        tag_in = f"in-mixed-{node['port']}"
        tag_out = outbound_tag(node["protocol"], node["port"])
        entry_proto = node.get("entryProto") or "mixed"
        if entry_proto == "ss":
            # Shadowsocks 单协议入站：aes-256-gcm + 节点 ss 密码
            ss_pass = node.get("ssPass") or node.get("authPass") or "relaypass"
            inbounds.append({
                "type": "shadowsocks", "tag": tag_in, "listen": listen_ip,
                "listen_port": node["port"],
                "method": "aes-256-gcm",
                "password": ss_pass,
            })
        else:
            inbounds.append({
                "type": "mixed", "tag": tag_in, "listen": listen_ip,
                "listen_port": node["port"],
                "users": [{"username": node.get("authUser") or "user", "password": node.get("authPass") or "pass"}],
            })
        cfg = node.get("rawConfig") or {}
        out_item = {"type": sb_type, "tag": tag_out}
        tls = _tls_enabled_dict(cfg)
        if sb_type == "shadowsocks":
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
                "method": cfg.get("method") or cfg.get("cipher", "aes-256-gcm"),
                "password": cfg.get("password", ""),
            })
        elif sb_type in ("vmess", "vless"):
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
                "uuid": cfg.get("uuid", ""),
            })
            if sb_type == "vmess":
                out_item["security"] = cfg.get("security", "auto")
            if tls:
                out_item["tls"] = tls
            elif sb_type == "vless":
                # vless 订阅节点（clash/vless://）几乎全走 TLS 端口；无 tls 配置时
                # 按 sni/server 推断。推断场景 server_name 是猜的（IP 节点证书无 SAN），
                # 必须 insecure 跳过证书校验，否则必然握手失败
                out_item["tls"] = {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or cfg.get("server", ""),
                    "insecure": True,
                }
            if cfg.get("flow"):
                out_item["flow"] = cfg["flow"]
            tr = _normalize_transport(cfg.get("transport") or cfg.get("streamSettings"))
            if tr:
                out_item["transport"] = tr
        elif sb_type == "trojan":
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
                "password": cfg.get("password", ""),
            })
            if tls:
                out_item["tls"] = tls
            else:
                # trojan 协议强制 TLS；订阅节点未带 tls 配置时按 sni 推断。
                # 推断的 server_name 是猜的，必须 insecure（同 vless 推断）
                out_item["tls"] = {
                    "enabled": True,
                    "server_name": cfg.get("sni") or cfg.get("server_name") or cfg.get("server", ""),
                    "insecure": True,
                }
            tr = _normalize_transport(cfg.get("transport") or cfg.get("streamSettings"))
            if tr:
                out_item["transport"] = tr
        elif sb_type in ("socks", "http"):
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
            })
            # sing-box 的 http outbound 要求带 password（无认证代理也必须补空串）
            out_item["username"] = cfg.get("username", "")
            out_item["password"] = cfg.get("password", "")
            if tls:
                out_item["tls"] = tls
        elif sb_type == "hysteria2":
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
                "password": cfg.get("password") or cfg.get("auth") or "",
            })
            tls_dict: Dict[str, Any] = {"enabled": True}
            # hysteria2 强制要求 tls.server_name，缺省用 server 兜底（否则整份配置 check 失败）
            tls_dict["server_name"] = (cfg.get("sni") or cfg.get("server_name")
                                       or cfg.get("server") or cfg.get("address", ""))
            # hy2 机场节点证书多与 SNI 不匹配，默认 insecure 跳过证书校验（实测连通关键，与前端一致）
            if cfg.get("insecure") in (False, "0", "false"):
                pass  # 显式关闭才不设 insecure
            else:
                tls_dict["insecure"] = True
            out_item["tls"] = tls_dict
            # hy2 obfs（clash 订阅常见 salamander）→ sing-box 对象形式
            obfs = cfg.get("obfs")
            if obfs:
                out_item["obfs"] = {"type": obfs,
                                    "password": cfg.get("obfsPassword") or cfg.get("obfs-password") or ""}
        elif sb_type == "tuic":
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
                "uuid": cfg.get("uuid", ""),
                "password": cfg.get("password", ""),
            })
            # sing-box 的 tuic outbound 强制 TLS
            if cfg.get("sni"):
                out_item["tls"] = {"enabled": True, "server_name": cfg["sni"]}
            else:
                out_item["tls"] = {"enabled": True}
        elif sb_type == "wireguard":
            out_item.update({
                "server": cfg.get("server") or cfg.get("address", ""),
                "server_port": int(cfg.get("server_port") or cfg.get("port") or 0),
                # sing-box wireguard outbound: private_key + peer_public_key + local_address
                "private_key": cfg.get("private_key") or cfg.get("local_private_key", ""),
                "peer_public_key": cfg.get("peer_public_key") or cfg.get("public_key", ""),
                "local_address": cfg.get("local_address") or ["10.0.0.2/32"],
            })
        outbounds.append(out_item)
        outbound_tag_set.add(tag_out)
        route_rules.append({"inbound": [tag_in], "outbound": tag_out})

    # 多域名轮询入口
    for rd in relay_domains:
        rd_id = rd["id"]
        rd_port = int(rd["port"])
        rd_in_tag = f"in-relay-{rd_id}"
        rd_out_tag = f"relay-auto-{rd_id}"
        selected_groups = rd.get("groups") or ["ALL"]
        rd_nodes = [n for n in nodes if n.get("status") != "disabled"
                    and ("ALL" in selected_groups or n.get("group") in selected_groups)]
        inbounds.append({
            "type": "mixed", "tag": rd_in_tag, "listen": listen_ip,
            "listen_port": rd_port,
            "users": [{"username": rd.get("authUser") or "relayuser", "password": rd.get("authPass") or "relaypass"}],
        })
        rd_targets = [outbound_tag(n["protocol"], n["port"]) for n in rd_nodes]
        rd_targets = [t for t in rd_targets if t in outbound_tag_set]
        # 用 selector 代替 urltest：轮询切换走 clash API PUT /proxies 运行时切换，
        # 只影响新连接、不断已有连接（热重载会全局断连，urltest 无法随机切换）。
        # 关闭随机轮询时：selector 由探活调度定时切到延迟最优节点（urltest 语义由面板模拟）。
        rd_selector = {
            "type": "selector", "tag": rd_out_tag,
            "outbounds": rd_targets if rd_targets else ["direct"],
        }
        # 随机轮询（注册机/爬虫场景）：启动时选中随机节点，之后定时器随机 PUT 切换
        if settings.get("randomRotateEnabled") and settings.get("randomRotateCurrent"):
            cur = settings["randomRotateCurrent"]
            if cur in rd_targets:
                rd_selector["default"] = cur
        outbounds.append(rd_selector)
        route_rules.append({"inbound": [rd_in_tag], "outbound": rd_out_tag})

    outbounds.append({"type": "direct", "tag": "direct"})
    outbounds.append({"type": "block", "tag": "block"})

    config = {
        "log": {"level": "info", "timestamp": True},
        "experimental": {
            "clash_api": {
                "external_controller": f"{CLASH_HOST}:{CLASH_PORT}",
                "secret": get_clash_secret(),
                "default_mode": "rule",
            }
        },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": {"rules": route_rules, "auto_detect_interface": True},
    }
    return {"config": config, "errors": errors}


def check_config(config: Dict[str, Any]) -> tuple:
    """sing-box check 校验。返回 (ok, message)。"""
    tmp = os.path.join(DATA_DIR, ".check.json")
    try:
        with open(tmp, "w") as f:
            json.dump(config, f)
        r = subprocess.run(
            [SINGBOX_BIN, "check", "-c", tmp],
            capture_output=True, text=True, timeout=20,
        )
        if r.returncode == 0:
            return True, "OK"
        return False, (r.stderr or r.stdout or "check failed").strip()
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except OSError:
                pass


def _detect_port_conflict(ports: Set[int]) -> List[int]:
    """端口冲突检测：独占 bind 探测。
    仅当 sing-box 运行时跳过其管理端口（此时确实被占）；未运行时这些端口
    实际空闲，若外部进程占用必须报冲突。clash API 端口（9095）也纳入检测。"""
    managed = set()
    if is_running():
        for n in db.list_nodes():
            managed.add(int(n["port"]))
        for rd in db.list_relay_domains():
            managed.add(int(rd["port"]))
        # sing-box 正运行时自己占着 clash API 端口，不算外部冲突
        managed.add(CLASH_PORT)
    conflicted = []
    for p in ports | {CLASH_PORT}:
        if p in managed:
            continue
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
        try:
            s.bind(("0.0.0.0", p))
        except OSError:
            conflicted.append(p)
        finally:
            s.close()
    return conflicted


def _atomic_write_config(config: Dict[str, Any]) -> None:
    """原子写 config.json + 旧配置留档 .bak。"""
    os.makedirs(DATA_DIR, exist_ok=True)
    if os.path.exists(CONFIG_PATH):
        try:
            os.replace(CONFIG_PATH, CONFIG_BAK_PATH)
        except OSError:
            pass
    tmp = CONFIG_PATH + ".tmp"
    with open(tmp, "w") as f:
        json.dump(config, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONFIG_PATH)


# ---------- 进程托管 ----------

def is_running() -> bool:
    """进程对象存在且尚未被 wait() 收割，视为运行中。

    注意：asyncio 的 Process.returncode 只有调用过 wait()/poll() 才会更新，
    直接读 returncode 判断"进程是否还活着"在进程已退出但未收割时为 False
    （永远返回 None），导致崩溃守护/防重入失效。统一用 _wait_task 判断。

    Docker host 网络部署下 sing-box 子进程可能进入宿主机 PID 空间（容器内
    看不到 /proc，_wait_task 立即 done），此时用 clash API 探测兜底判断——
    host 网络共享 127.0.0.1，容器内外都能访问 clash API 端口（9095）。
    """
    global _proc
    if _proc is not None and (_wait_task is None or not _wait_task.done()):
        return True
    # 兜底：clash API 探测（host 网络下容器内外一致）
    try:
        import urllib.request
        req = urllib.request.Request(
            f"http://{CLASH_HOST}:{CLASH_PORT}/version",
            headers={"Authorization": f"Bearer {get_clash_secret()}"},
        )
        r = urllib.request.urlopen(req, timeout=1)
        return r.status == 200
    except Exception:
        return False


async def _reap_proc() -> None:
    """收割 sing-box 子进程并打印退出信息。

    进程退出后本任务 done()，is_running() 据此返回 False（不能把 _wait_task 置
    None——那样 is_running 会误判"活着"）。注意 asyncio 的 Process.returncode
    只有调用过 wait()/poll() 才会更新，直接读它永远显示进程活着。
    """
    proc = _proc
    if proc is None:
        return
    try:
        await proc.wait()
    except Exception:
        return
    # 退出后回读 singbox.log 尾行，把真实死因（如 bind: address already in use）带上
    tail = ""
    try:
        with open(LOG_PATH, "r", errors="replace") as f:
            lines = f.read().splitlines()[-3:]
        tail = " | ".join(l for l in lines if l.strip())[-400:]
    except Exception:
        pass
    print(f"[singbox] 进程已退出 code={proc.returncode} {tail}")


async def start() -> bool:
    """用 config.json 启动（缺失时尝试 .bak）。返回是否成功启动。"""
    async with _op_lock:
        return await _start_unlocked()


async def _start_unlocked() -> bool:
    """无锁内核版 start（调用方需已持 _op_lock）。"""
    global _proc, _started_at, _logf, _wait_task
    if is_running():
        return True
    cfg = CONFIG_PATH
    if not os.path.exists(cfg):
        cfg = CONFIG_BAK_PATH
    if not os.path.exists(cfg):
        return False
    # 先校验
    try:
        with open(cfg) as f:
            data = json.load(f)
    except Exception:
        return False
    ok, _ = await asyncio.to_thread(check_config, data)
    if not ok:
        return False
    os.makedirs(DATA_DIR, exist_ok=True)
    # 关闭旧句柄避免 fd 泄漏
    if _logf is not None:
        try:
            _logf.close()
        except Exception:
            pass
    _logf = open(LOG_PATH, "a")
    _proc = await asyncio.create_subprocess_exec(
        SINGBOX_BIN, "run", "-c", cfg, "-D", DATA_DIR,
        stdout=_logf, stderr=_logf,
    )
    _started_at = time.time()
    # 关键：spawn 收割任务——asyncio 的 Process.returncode 不调用 wait() 永远不会更新，
    # 崩溃守护靠这个任务感知进程退出，否则 sing-box 死后守护会永远以为它活着。
    _wait_task = asyncio.create_task(_reap_proc())
    # 启动后短观察：若立即退出（如 clash API 端口被占），把真实死因从日志带回。
    # 注意不能用 wait_for——它超时后会取消被等待的收割任务，守护就废了。
    done, _ = await asyncio.wait({_wait_task}, timeout=2.0)
    if _wait_task in done:
        return False  # 进程已退出（_reap_proc 已把退出信息打印到 stdout）
    return True  # 存活超过 2s，视为启动成功


async def stop() -> None:
    global _proc, _logf, _wait_task
    async with _op_lock:
        if _proc is not None:
            try:
                _proc.send_signal(signal.SIGTERM)
                try:
                    await asyncio.wait_for(_proc.wait(), timeout=5)
                except asyncio.TimeoutError:
                    _proc.kill()
            except Exception:
                pass
            # 取消收割任务，避免其 try/finally 中访问已回收的 _proc
            if _wait_task is not None:
                _wait_task.cancel()
                try:
                    await _wait_task
                except (asyncio.CancelledError, Exception):
                    pass
                _wait_task = None
            _proc = None
            # 关闭日志句柄避免 fd 泄漏
            if _logf is not None:
                try:
                    _logf.close()
                except Exception:
                    pass
                _logf = None
            return
        # _proc 丢失但 clash 探测仍活着（如 uvicorn 崩溃重启后 sing-box 残留），
        # 兜底用 pkill 按命令行特征清理，避免面板显示已停止而 sing-box 仍占用端口。
        if is_running():
            try:
                # 精确匹配本面板的 config 路径，避免误杀宿主其他 sing-box 实例
                subprocess.run(["pkill", "-TERM", "-f", f"sing-box run -c {CONFIG_PATH}"],
                               capture_output=True, timeout=5)
            except Exception:
                pass


async def reload_config() -> bool:
    """SIGHUP 热重载（sing-box 收到后内部 check() 重读磁盘配置，失败保留旧实例）。

    send_signal 只证明信号已发出，不代表重载成功——sing-box 收到 SIGHUP 后
    先 check()，新配置无效会保留旧实例。因此这里在发出后轮询 clash API：
    旧实例 close 再起新实例期间 /version 短暂不可达，恢复即视为重载成功。

    host 网络下 sing-box 可能逃逸出容器 PID 空间（_proc 为 None 但 clash 探测
    运行中），此时无法 send_signal，改用 pkill -HUP 按 config 路径匹配。
    """
    global _proc
    if not is_running():
        return False
    if _proc is not None:
        try:
            _proc.send_signal(signal.SIGHUP)
        except Exception:
            return False
    else:
        # _proc 丢失但 sing-box 仍在跑：pkill -HUP 按本面板 config 路径精确匹配
        try:
            subprocess.run(["pkill", "-HUP", "-f", f"sing-box run -c {CONFIG_PATH}"],
                           capture_output=True, timeout=5)
        except Exception:
            return False
    # 等 clash API 恢复（旧实例关闭到新实例就绪的窗口 <1s 左右；最多 5s）
    hdrs = {"Authorization": f"Bearer {get_clash_secret()}"}
    try:
        async with httpx.AsyncClient(timeout=1.0) as client:
            for _ in range(10):
                await asyncio.sleep(0.5)
                try:
                    r = await client.get(f"{clash_base()}/version", headers=hdrs)
                    if r.status_code == 200:
                        return True
                except Exception:
                    pass
    except Exception:
        pass
    # clash API 一直没恢复——旧实例可能仍在（check 失败）或已死，交由调用方验证兜底
    return False


async def status() -> Dict[str, Any]:
    running = is_running()
    version = None
    if running:
        version = await asyncio.to_thread(_get_singbox_version)
    uptime = (time.time() - _started_at) if (running and _started_at) else None
    clash_ok = False
    if running:
        try:
            async with httpx.AsyncClient(timeout=1.5) as client:
                r = await client.get(f"{clash_base()}/version",
                                     headers={"Authorization": f"Bearer {get_clash_secret()}"})
                clash_ok = r.status_code == 200
        except Exception:
            clash_ok = False
    return {
        "running": running,
        # host 网络下 sing-box 可能逃逸出容器 PID 空间（_proc 为 None 但 clash 探测运行中）
        "pid": _proc.pid if (running and _proc is not None) else None,
        "uptime": uptime,
        "version": version,
        "clashApiOk": clash_ok,
        "controller": f"{CLASH_HOST}:{CLASH_PORT}",
    }


def _get_singbox_version() -> Optional[str]:
    try:
        r = subprocess.run([SINGBOX_BIN, "version"], capture_output=True, text=True, timeout=10)
        return r.stdout.strip().splitlines()[0] if r.stdout else None
    except Exception:
        return None


async def apply_config(provided: Optional[Dict] = None) -> Dict[str, Any]:
    """生成→校验→原子写→热重载→验证 clash API。失败回滚。全程加锁防并发竞态。"""
    async with _op_lock:
        return await _apply_config_impl(provided)


async def _apply_config_impl(provided: Optional[Dict] = None) -> Dict[str, Any]:
    """生成→校验→原子写→热重载→验证 clash API。失败回滚。"""
    global _last_good_config
    if provided is not None:
        config, errors = provided, []
    else:
        built = build_config()
        config, errors = built["config"], built["errors"]

    # 1. 端口冲突检测（sing-box 未运行时也检查全部端口，避免漏报）
    all_ports = set()
    for ib in config.get("inbounds", []):
        if ib.get("listen_port"):
            all_ports.add(int(ib["listen_port"]))
    conflict = await asyncio.to_thread(_detect_port_conflict, all_ports)
    if conflict:
        return {
            "ok": False,
            "message": f"端口被占用: {conflict}",
            "running": is_running(),
            "clashApiOk": False,
            "errors": errors,
        }

    # 2. check 校验（失败不落地，用 to_thread 避免阻塞事件循环）
    ok, msg = await asyncio.to_thread(check_config, config)
    if not ok:
        return {
            "ok": False,
            "message": f"配置校验失败: {msg}",
            "running": is_running(),
            "clashApiOk": False,
            "errors": errors,
        }

    # 3. 原子写 + 留档（先存旧好配置，再更新 _last_good_config，避免回滚自回滚）
    prev_good = _last_good_config
    _atomic_write_config(config)
    _last_good_config = config

    # 4. 运行中则热重载，未运行则启动（_apply_config_impl 已持锁，用无锁内核版）
    if is_running():
        await reload_config()
    else:
        started = await _start_unlocked()
        if not started:
            return {
                "ok": False,
                "message": "sing-box 启动失败（请查看 singbox.log）",
                "running": False,
                "clashApiOk": False,
                "errors": errors,
            }

    # 5. 验证 clash API 可达（5s 内轮询，async httpx 不阻塞，带 Bearer secret）
    clash_ok = False
    clash_hdrs = {"Authorization": f"Bearer {get_clash_secret()}"}
    async with httpx.AsyncClient(timeout=1.5) as client:
        for _ in range(10):
            try:
                r = await client.get(f"{clash_base()}/version", headers=clash_hdrs)
                if r.status_code == 200:
                    clash_ok = True
                    break
            except Exception:
                pass
            await asyncio.sleep(0.5)

    if not clash_ok:
        # 回滚：用 prev_good（更新前的上一份好配置）重载
        if prev_good:
            _atomic_write_config(prev_good)
            if is_running():
                await reload_config()
            else:
                await _start_unlocked()
        return {
            "ok": True,
            "message": "配置已应用但 clash API 未就绪，已回滚到上一份配置",
            "running": is_running(),
            "clashApiOk": False,
            "errors": errors,
        }

    return {
        "ok": True,
        "message": "配置应用成功，sing-box 已热重载",
        "running": is_running(),
        "clashApiOk": True,
        "errors": errors,
    }


def get_last_good_config() -> Optional[Dict]:
    return _last_good_config


def get_proc() -> Optional[asyncio.subprocess.Process]:
    return _proc
