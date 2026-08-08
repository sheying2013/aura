"""订阅后端代理：httpx 拉取（解决前端 CORS）、内容解析（移植 subs.js）、last-good 快照、去重导入。

解析格式：Base64 列表 / Clash YAML(proxies:) / JSON(outbounds|proxies|数组) / 明文链接
协议：ss/vmess/vless/trojan/ssr/hysteria2/tuic
"""
import base64
import ipaddress
import json
import re
import socket
from typing import Any, Dict, List, Optional
from urllib.parse import unquote, urlparse

import httpx

import db

_UA = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
REFRESH_INTERVAL = 6 * 60 * 60 * 1000  # 6h


# ---------- 拉取 ----------

def _is_public_url(url: str) -> bool:
    """SSRF 防护：仅允许公网 http/https。对域名也做 DNS 解析检查。"""
    try:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            return False
        host = p.hostname or ""
        if host in ("localhost", "127.0.0.1", "::1"):
            return False
        # 字面 IP 直接检查
        try:
            ip = ipaddress.ip_address(host)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
                return False
            return True
        except ValueError:
            pass  # 不是字面 IP，走域名解析
        # 域名：DNS 解析后逐个 IP 检查
        try:
            for res in socket.getaddrinfo(host, None):
                resolved_ip = ipaddress.ip_address(res[4][0])
                if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local or resolved_ip.is_reserved:
                    return False
        except (socket.gaierror, OSError):
            return False  # 解析失败视为不安全
        return True
    except Exception:
        return False


async def fetch_subscription(url: str) -> Dict[str, Any]:
    if not _is_public_url(url):
        return {"ok": False, "error": "仅允许公网 http/https 订阅 URL"}
    try:
        async with httpx.AsyncClient(follow_redirects=True, timeout=15.0) as client:
            resp = await client.get(url, headers={"User-Agent": _UA})
            if resp.status_code >= 400:
                return {"ok": False, "status": resp.status_code, "error": f"HTTP {resp.status_code}"}
            return {"ok": True, "status": resp.status_code, "content": resp.text}
    except Exception as e:
        return {"ok": False, "error": str(e)}


# ---------- 基础工具 ----------

def _b64_decode(s: str) -> Optional[str]:
    try:
        t = s.replace("-", "+").replace("_", "/")
        t += "=" * (-len(t) % 4)
        raw = base64.b64decode(t)
        return raw.decode("utf-8", errors="replace")
    except Exception:
        return None


def _b64_detect(s: str) -> bool:
    return len(s) > 40 and bool(re.fullmatch(r"[A-Za-z0-9+/=_-]+", s.strip()))


def _parse_base64_pwd(s: str) -> str:
    d = _b64_decode(s)
    return d if d else s


# ---------- 单链接解析 ----------

def _parse_link(line: str) -> Optional[Dict[str, Any]]:
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    name = ""
    hi = line.find("#")
    if hi != -1:
        try:
            name = unquote(line[hi + 1:])
        except Exception:
            name = line[hi + 1:]
        line = line[:hi]

    try:
        # ss:// — SIP002 或 legacy
        if line.startswith("ss://"):
            body = line[5:]
            if "@" in body:
                # SIP002: method:pass@host:port
                cred, hostport = body.rsplit("@", 1)
                hp = hostport.rsplit(":", 1)
                if len(hp) != 2:
                    return None
                if ":" in cred and not cred.startswith("aes"):
                    method, password = cred.split(":", 1)
                else:
                    # base64 编码的 method:pass
                    dec = _b64_decode(cred) or cred
                    if ":" in dec:
                        method, password = dec.split(":", 1)
                    else:
                        return None
                return {
                    "name": name or f"ss-{hp[0]}", "protocol": "shadowsocks",
                    "rawConfig": {"server": hp[0], "server_port": int(hp[1]),
                                  "method": method, "password": password},
                }
            else:
                # legacy: base64(method:pass@host:port)
                dec = _b64_decode(body) or body
                m = re.match(r"^([^:]+):([^@]+)@([^:]+):(\d+)$", dec)
                if not m:
                    return None
                return {
                    "name": name or f"ss-{m.group(3)}", "protocol": "shadowsocks",
                    "rawConfig": {"server": m.group(3), "server_port": int(m.group(4)),
                                  "method": m.group(1), "password": m.group(2)},
                }
        # vmess:// — base64 JSON
        if line.startswith("vmess://"):
            dec = _b64_decode(line[8:])
            if not dec:
                return None
            try:
                data = json.loads(dec)
            except Exception:
                return None
            port = int(data.get("port", 0))
            return {
                "name": name or data.get("ps", f"vmess-{data.get('add', '')}"),
                "protocol": "vmess",
                "rawConfig": {"server": data.get("add", ""), "server_port": port,
                              "uuid": data.get("id", ""), "method": data.get("method", "auto"),
                              "security": data.get("security", "auto"),
                              "alterId": data.get("aid", 0)},
            }
        # vless:// / trojan:// — URI
        for proto, sb_type in (("vless", "vless"), ("trojan", "trojan")):
            if line.startswith(f"{proto}://"):
                body = line[len(proto) + 3:]
                cred, hostport = body.rsplit("@", 1) if "@" in body else ("", body)
                hp = hostport.rsplit(":", 1)
                if len(hp) != 2:
                    return None
                params = {}
                if "?" in hp[1]:
                    hp[1], qs = hp[1].split("?", 1)
                    for kv in qs.split("&"):
                        if "=" in kv:
                            k, v = kv.split("=", 1)
                            params[k] = unquote(v)
                rc: Dict[str, Any] = {"server": hp[0], "server_port": int(hp[1]),
                                      "uuid": cred, "password": cred}
                rc["tls"] = {"enabled": True}
                if params.get("sni"):
                    rc["tls"]["server_name"] = params["sni"]
                if params.get("fp"):
                    rc["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
                if params.get("flow"):
                    rc["flow"] = params["flow"]
                if params.get("type", "tcp") != "tcp":
                    rc["transport"] = {"type": params["type"]}
                if params.get("security") == "reality":
                    rc["tls"]["reality"] = {"enabled": True,
                                            "public_key": params.get("pbk", ""),
                                            "short_id": params.get("sid", "")}
                return {
                    "name": name or f"{proto}-{hp[0]}", "protocol": sb_type, "rawConfig": rc,
                }
        # hysteria2://
        if line.startswith("hysteria2://"):
            body = line[len("hysteria2://"):]
            m = re.match(r"^([^@]*)@?([^:]+):(\d+)(.*)$", body)
            if not m:
                return None
            params = dict(re.findall(r"([^&=]+)=([^&]+)", m.group(4)))
            return {
                "name": name or f"hy2-{m.group(2)}", "protocol": "hysteria2",
                "rawConfig": {"server": m.group(2), "server_port": int(m.group(3)),
                              "password": m.group(1) or params.get("auth", ""),
                              "sni": params.get("sni", "")},
            }
        # tuic://
        if line.startswith("tuic://"):
            body = line[len("tuic://"):]
            m = re.match(r"^([^@]+)@([^:]+):(\d+)(.*)$", body)
            if not m:
                return None
            parts = m.group(1).split(":")
            params = dict(re.findall(r"([^&=]+)=([^&]+)", m.group(4)))
            return {
                "name": name or f"tuic-{m.group(2)}", "protocol": "tuic",
                "rawConfig": {"server": m.group(2), "server_port": int(m.group(3)),
                              "uuid": parts[0], "password": parts[1] if len(parts) > 1 else "",
                              "sni": params.get("sni", "")},
            }
        # ssr://
        if line.startswith("ssr://"):
            dec = _b64_decode(line[6:])
            if not dec:
                return None
            base = dec.split("/?")[0]
            parts = base.split(":")
            if len(parts) < 6:
                return None
            return {
                "name": name or f"ssr-{parts[0]}", "protocol": "ssr",
                "rawConfig": {"server": parts[0], "server_port": int(parts[1]),
                              "protocol": parts[2], "method": parts[3], "obfs": parts[4],
                              "password": _parse_base64_pwd(parts[5])},
            }
    except Exception:
        return None
    return None


# ---------- 内容类型检测与解析 ----------

def _detect_type(content: str) -> str:
    t = content.strip()
    if t.startswith("{") or t.startswith("["):
        return "json"
    if re.search(r"^\s*proxies:\s*$", t, re.MULTILINE) or re.search(r"^\s*proxies:\s*\[", t, re.MULTILINE):
        return "clash"
    if "\n" in t and re.search(r"^\s*(ss|vmess|vless|trojan|ssr|hysteria2|tuic)://", t, re.MULTILINE):
        return "urllist"
    if re.match(r"^(ss|vmess|vless|trojan|ssr|hysteria2|tuic)://", t):
        return "urllist"
    if _b64_detect(t):
        return "b64"
    return "unknown"


def _parse_clash_yaml(content: str) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    lines = content.split("\n")
    start = -1
    for i, l in enumerate(lines):
        if re.match(r"^\s*proxies:\s*$", l):
            start = i + 1
            break
    if start == -1:
        return nodes
    blocks: List[List[str]] = []
    cur: Optional[List[str]] = None
    for i in range(start, len(lines)):
        l = lines[i]
        if i > start and re.match(r"^[a-zA-Z][\w-]*:\s*$", l):
            break
        if re.match(r"^\s*-\s+", l):
            if cur:
                blocks.append(cur)
            cur = [re.sub(r"^\s*-\s+", "", l)]
        elif cur:
            cur.append(l)
    if cur:
        blocks.append(cur)

    for block in blocks:
        obj: Dict[str, Any] = {}
        for l in block:
            kv = re.match(r"^\s*([\w-]+):\s*(.*)$", l)
            if kv and kv.group(1) not in ("ws-opts", "grpc-opts", "reality-opts", "plugin-opts", "ss-opts", "xhttp-opts", "tls-opts", "http-opts"):
                obj[kv.group(1)] = kv.group(2).strip().strip("'\"")
        for i, l in enumerate(block):
            opm = re.match(r"^\s*([\w-]+)-opts:\s*$", l)
            if opm:
                sub: Dict[str, Any] = {}
                for j in range(i + 1, len(block)):
                    if not re.match(r"^\s+\S", block[j]):
                        break
                    kv = re.match(r"^\s+([\w-]+):\s*(.*)$", block[j])
                    if kv:
                        sub[kv.group(1)] = kv.group(2).strip().strip("'\"")
                obj[opm.group(1) + "-opts"] = sub
        if not obj.get("name") or not obj.get("type"):
            continue
        proto_map = {"ss": "ss", "ssr": "ssr", "vmess": "vmess", "vless": "vless",
                     "trojan": "trojan", "hysteria2": "hysteria2", "wireguard": "wireguard", "tuic": "tuic"}
        proto = proto_map.get(obj.get("type", ""))
        if not proto:
            continue
        # 归一化：clash tls 字段可能是字符串 'true'/'false' → 转 dict
        tls_raw = obj.get("tls")
        if isinstance(tls_raw, str):
            obj["tls"] = {"enabled": tls_raw.lower() == "true"}
        # 归一化：clash network + ws-opts/grpc-opts → sing-box transport
        if obj.get("network") and obj.get("network") != "tcp":
            transport = {"type": obj["network"]}
            opts_key = obj["network"] + "-opts"
            opts = obj.get(opts_key)
            if isinstance(opts, dict):
                for k, v in opts.items():
                    transport[k] = v
            obj["transport"] = transport
        # clash ss 用 cipher 键 → method 兼容已在 config_manager 处理
        nodes.append({"name": obj["name"], "protocol": proto, "rawConfig": obj})
    return nodes


def _parse_json_content(content: str) -> List[Dict[str, Any]]:
    nodes: List[Dict[str, Any]] = []
    try:
        data = json.loads(content)
        if isinstance(data, dict) and data.get("outbounds"):
            data = data["outbounds"]
        elif isinstance(data, dict) and data.get("proxies"):
            data = data["proxies"]
        elif isinstance(data, list):
            flat = []
            for elem in data:
                if isinstance(elem, dict) and elem.get("outbounds"):
                    ob = elem["outbounds"][0] if elem["outbounds"] else None
                    if ob:
                        flat.append({"name": elem.get("remarks") or ob.get("tag", ""),
                                     "type": ob.get("protocol"), "settings": ob.get("settings"),
                                     "streamSettings": ob.get("streamSettings")})
                else:
                    flat.append(elem)
            data = flat
        if not isinstance(data, list):
            return nodes
        for o in data:
            if not isinstance(o, dict):
                continue
            otype = o.get("type") or o.get("protocol")
            oname = o.get("name") or o.get("remark") or o.get("ps") or o.get("remarks") or ""
            if otype in ("vmess", "vless", "trojan", "shadowsocks", "ss", "hysteria2", "tuic", "wireguard"):
                rc = dict(o)
                rc.pop("name", None)
                nodes.append({
                    "name": oname or f"{o.get('server','')}:{o.get('server_port') or o.get('port','')}",
                    "protocol": "ss" if otype == "shadowsocks" else otype,
                    "rawConfig": rc,
                })
    except Exception:
        pass
    return nodes


def _parse_b64_content(content: str) -> List[Dict[str, Any]]:
    dec = _b64_decode(content.strip())
    if not dec:
        return []
    return [n for n in (_parse_link(l) for l in dec.split("\n")) if n]


def parse_content(content: str) -> List[Dict[str, Any]]:
    ctype = _detect_type(content)
    if ctype == "b64":
        return _parse_b64_content(content)
    if ctype == "urllist":
        return [n for n in (_parse_link(l) for l in content.split("\n")) if n]
    if ctype == "clash":
        return _parse_clash_yaml(content)
    if ctype == "json":
        return _parse_json_content(content)
    return []


# ---------- 去重导入 ----------

def import_nodes(sub_id: str, group: str, nodes: List[Dict[str, Any]], stale: bool = False) -> Dict[str, Any]:
    """把解析出的节点导入 DB（对齐前端：按 server:port 去重、分组继承、随机 auth、subId 关联）。"""
    from db import infer_segment, get_next_available_port, random_auth, create_node_batch

    prepared: List[Dict[str, Any]] = []
    for pn in nodes:
        rc = pn.get("rawConfig") or {}
        seg = infer_segment(pn.get("name", ""), pn.get("protocol", ""))
        port = get_next_available_port(None, seg)
        user, passwd = random_auth(port)
        prepared.append({
            "id": db.new_node_id(),
            "name": pn.get("name", "未命名"),
            "protocol": pn.get("protocol", "shadowsocks"),
            "group": group,
            "port": port,
            "segment": seg,
            "authUser": user,
            "authPass": passwd,
            "status": "offline",
            "ping": 0,
            "exitIp": "N/A",
            "upTraffic": 0,
            "downTraffic": 0,
            "rawConfig": rc,
            "subId": sub_id,
            "stale": stale,
            "selected": False,
            "entryProto": "mixed",
            "ssPass": None,
        })
    return create_node_batch(prepared)


# ---------- 刷新 ----------

async def refresh_sub(sub: Dict[str, Any]) -> Dict[str, Any]:
    """拉取→解析→导入；失败用 last-good snapshot 兜底标 stale。"""
    res = await fetch_subscription(sub["url"])
    if res["ok"]:
        nodes = parse_content(res["content"])
        if not nodes:
            sub = db.update_sub(sub["id"], {"last_error": "解析 0 个节点"})
            return {"id": sub["id"], "ok": False, "count": 0, "stale": False, "imported": 0, "error": "解析 0 个节点"}
        imported = import_nodes(sub["id"], sub.get("group", "订阅节点"), nodes, stale=False)
        db.update_sub(sub["id"], {
            "last_refresh": int(__import__("time").time() * 1000),
            "node_count": len(nodes),
            "last_error": None,
            "snapshot": json.dumps(nodes, ensure_ascii=False),
        })
        # 有新增节点 → 重建 sing-box 配置使新节点立即生效（无新增则跳过热重载）
        if imported["created"] > 0:
            try:
                import config_manager
                await config_manager.apply_config()
            except Exception:
                pass
        return {"id": sub["id"], "ok": True, "count": len(nodes), "stale": False,
                "imported": imported["created"], "error": None}

    # 失败：last-good 兜底
    snap = sub.get("snapshot")
    if snap:
        try:
            nodes = json.loads(snap)
            if nodes:
                imported = import_nodes(sub["id"], sub.get("group", "订阅节点"), nodes, stale=True)
                # 兜底：已有节点也标 stale（快照是过期数据）
                db.mark_nodes_stale_by_sub(sub["id"])
                db.update_sub(sub["id"], {"last_error": res.get("error")})
                return {"id": sub["id"], "ok": False, "count": len(nodes), "stale": True,
                        "imported": imported["created"], "error": res.get("error")}
        except Exception:
            pass
    db.update_sub(sub["id"], {"last_error": res.get("error")})
    return {"id": sub["id"], "ok": False, "count": 0, "stale": False, "imported": 0, "error": res.get("error")}


async def refresh_subs(ids: Optional[List[str]] = None, all_: bool = True) -> List[Dict[str, Any]]:
    subs = db.list_subs()
    if not all_ and ids:
        subs = [s for s in subs if s["id"] in ids]
    results = []
    for s in subs:
        if not s.get("enabled", True):
            continue
        results.append(await refresh_sub(s))
    return results
