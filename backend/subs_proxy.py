"""订阅后端代理：httpx 拉取（解决前端 CORS）、内容解析（移植 subs.js）、last-good 快照、去重导入。

解析格式：Base64 列表 / Clash YAML(proxies:) / JSON(outbounds|proxies|数组) / 明文链接
协议：ss/vmess/vless/trojan/ssr/hysteria2/tuic
"""
import base64
import ipaddress
import json
import re
import socket
import time
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
        async with httpx.AsyncClient(follow_redirects=False, timeout=15.0) as client:
            resp = await client.get(url, headers={"User-Agent": _UA})
            # 手动处理重定向，逐次校验目标 URL 的安全性
            for _ in range(5):
                if 300 <= resp.status_code < 400:
                    loc = resp.headers.get("location", "")
                    if not loc or not _is_public_url(loc):
                        return {"ok": False, "error": "重定向目标 URL 不安全（内网地址）"}
                    resp = await client.get(loc, headers={"User-Agent": _UA})
                else:
                    break
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
            rc: Dict[str, Any] = {"server": data.get("add", ""), "server_port": port,
                                  "uuid": data.get("id", ""), "method": data.get("method", "auto"),
                                  "security": data.get("security", "auto"),
                                  "alterId": data.get("aid", 0)}
            # vmess base64 JSON 标准字段：tls=over-tls, sni, net=ws/grpc, host, path, fp
            if str(data.get("tls", "")).lower() in ("tls", "1", "true"):
                rc["tls"] = {"enabled": True}
                if data.get("sni"):
                    rc["tls"]["server_name"] = data["sni"]
                fp = data.get("fp")
                if fp and fp.lower() not in ("none", "random"):
                    rc["tls"]["utls"] = {"enabled": True, "fingerprint": fp}
                if str(data.get("allowInsecure", "")).lower() in ("1", "true"):
                    rc["tls"]["insecure"] = True
            net = data.get("net", "")
            if net and net != "tcp":
                rc["transport"] = {"type": net}
                if data.get("path"):
                    rc["transport"]["path"] = data["path"]
                if data.get("host"):
                    if net == "grpc":
                        rc["transport"]["service_name"] = data["host"]
                    else:
                        rc["transport"]["headers"] = {"Host": data["host"]}
            return {
                "name": name or data.get("ps", f"vmess-{data.get('add', '')}"),
                "protocol": "vmess",
                "rawConfig": rc,
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
                elif params.get("servername"):
                    rc["tls"]["server_name"] = params["servername"]
                if params.get("alpn"):
                    rc["tls"]["alpn"] = [a for a in params["alpn"].split(",") if a]
                if params.get("fp"):
                    rc["tls"]["utls"] = {"enabled": True, "fingerprint": params["fp"]}
                # vless/trojan 常见 allowInsecure / insecure 参数
                for k in ("allowInsecure", "insecure"):
                    if params.get(k) in ("1", "true", "yes"):
                        rc["tls"]["insecure"] = True
                if params.get("flow"):
                    rc["flow"] = params["flow"]
                if params.get("type", "tcp") != "tcp":
                    rc["transport"] = {"type": params["type"]}
                    if params.get("path"):
                        rc["transport"]["path"] = params["path"]
                    if params.get("host"):
                        # ws 传输 host 在 headers.Host；http/h2 传输 host 在 host 数组
                        t = rc.get("transport", {}).get("type", "")
                        if t in ("http", "h2"):
                            rc["transport"]["host"] = [params["host"]]
                        else:
                            rc["transport"]["headers"] = {"Host": params["host"]}
                    if params.get("serviceName"):
                        rc["transport"]["service_name"] = params["serviceName"]
                if params.get("security") == "reality":
                    rc["tls"]["reality"] = {"enabled": True,
                                            "public_key": params.get("pbk", ""),
                                            "short_id": params.get("sid", "")}
                    # sing-box reality client 强制要求 uTLS（无 fp 默认 chrome）
                    if "utls" not in rc["tls"]:
                        rc["tls"]["utls"] = {"enabled": True,
                                             "fingerprint": params.get("fp") or "chrome"}
                return {
                    "name": name or f"{proto}-{hp[0]}", "protocol": sb_type, "rawConfig": rc,
                }
        # hysteria2://
        if line.startswith("hysteria2://"):
            body = line[len("hysteria2://"):]
            m = re.match(r"^([^@]*)@?([^:]+):(\d+)(.*)$", body)
            if not m:
                return None
            qs = m.group(4).lstrip("?")
            params = dict(re.findall(r"([^&=]+)=([^&]+)", qs))
            rc: Dict[str, Any] = {"server": m.group(2), "server_port": int(m.group(3)),
                                  "password": m.group(1) or params.get("auth", ""),
                                  "sni": params.get("sni", "")}
            if params.get("insecure") in ("1", "true", "yes"):
                rc["insecure"] = True
            if params.get("obfs"):
                rc["obfs"] = params["obfs"]
                rc["obfsPassword"] = params.get("obfs-password", "")
            return {
                "name": name or f"hy2-{m.group(2)}", "protocol": "hysteria2",
                "rawConfig": rc,
            }
        # tuic://
        if line.startswith("tuic://"):
            body = line[len("tuic://"):]
            m = re.match(r"^([^@]+)@([^:]+):(\d+)(.*)$", body)
            if not m:
                return None
            parts = m.group(1).split(":")
            params = dict(re.findall(r"([^&=]+)=([^&]+)", m.group(4).lstrip("?")))
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

        # 两遍扫描：先定位所有 *-opts 子块的行区间（缩进大于 opts 键的行）
        opts_ranges: List[tuple] = []
        for i, l in enumerate(block):
            opm0 = re.match(r"^(\s*)[\w-]+-opts:\s*$", l)
            if opm0:
                base0 = len(opm0.group(1))
                j = i + 1
                while j < len(block):
                    lm = re.match(r"^(\s+)", block[j])
                    if not lm or len(lm.group(1)) <= base0:
                        break
                    j += 1
                opts_ranges.append((i, j))
        # 主循环：跳过 *-opts 子块区间内的行（避免 path/Host/tls 污染顶层）
        for i, l in enumerate(block):
            if any(s <= i < e for s, e in opts_ranges):
                continue
            kv = re.match(r"^\s*([\w-]+):\s*(.*)$", l)
            if kv:
                obj[kv.group(1)] = kv.group(2).strip().strip("'\"")
        for i, l in enumerate(block):
            opm = re.match(r"^\s*-?\s*([\w-]+)-opts:\s*$", l)
            if opm:
                base_indent = len(l) - len(l.lstrip())
                sub: Dict[str, Any] = {}
                for j in range(i + 1, len(block)):
                    kv = re.match(r"^(\s+)([\w-]+):\s*(.*)$", block[j])
                    if not kv or len(kv.group(1)) <= base_indent:
                        break  # 缩进不足 = 属于 opts 之外的兄弟字段
                    indent = len(kv.group(1))
                    key, val = kv.group(2), kv.group(3).strip().strip("'\"")
                    if key == "headers" and not val:
                        # headers 嵌套子块（如 Host: xxx）→ dict
                        hdrs: Dict[str, Any] = {}
                        for k2 in range(j + 1, len(block)):
                            kv2 = re.match(r"^(\s+)([\w-]+):\s*(.*)$", block[k2])
                            if not kv2 or len(kv2.group(1)) <= indent:
                                break
                            hdrs[kv2.group(2)] = kv2.group(3).strip().strip("'\"")
                        sub["headers"] = hdrs
                    else:
                        sub[key] = val
                obj[opm.group(1) + "-opts"] = sub
        if not obj.get("name") or not obj.get("type"):
            continue
        proto_map = {"ss": "ss", "ssr": "ssr", "vmess": "vmess", "vless": "vless",
                     "trojan": "trojan", "hysteria2": "hysteria2", "wireguard": "wireguard", "tuic": "tuic"}
        proto = proto_map.get(obj.get("type", ""))
        if not proto:
            continue

        def _bool(v: Any) -> bool:
            if isinstance(v, bool):
                return v
            return str(v).strip().lower() in ("true", "1", "yes", "on")

        # 端口/数值统一转 int（clash YAML 解析后是字符串）
        for pk in ("port", "server_port"):
            if pk in obj:
                try:
                    obj[pk] = int(obj[pk])
                except (TypeError, ValueError):
                    pass

        # TLS 归一化：tls 字段（bool/'true'）+ sni/server_name + skip-cert-verify → sing-box tls dict
        tls_raw = obj.get("tls")
        tls_enabled = _bool(tls_raw) if tls_raw is not None else None
        sni = obj.get("sni") or obj.get("server_name") or ""
        skip_verify = _bool(obj.get("skip-cert-verify")) if obj.get("skip-cert-verify") is not None else False
        if tls_enabled is not None or sni or skip_verify:
            tls_dict: Dict[str, Any] = {"enabled": bool(tls_enabled) if tls_enabled is not None else True}
            if sni:
                tls_dict["server_name"] = sni
            if skip_verify:
                tls_dict["insecure"] = True
            if obj.get("fingerprint") or obj.get("client-fingerprint"):
                tls_dict["utls"] = {"enabled": True,
                                    "fingerprint": obj.get("fingerprint") or obj.get("client-fingerprint")}
            if obj.get("reality-opts"):
                ropts = obj["reality-opts"]
                tls_dict["reality"] = {"enabled": True,
                                       "public_key": ropts.get("public-key") or ropts.get("public_key", ""),
                                       "short_id": ropts.get("short-id") or ropts.get("short_id", "")}
                # sing-box reality client 强制要求 uTLS（无 fp 默认 chrome 指纹）
                if "utls" not in tls_dict:
                    tls_dict["utls"] = {"enabled": True,
                                        "fingerprint": obj.get("fingerprint") or obj.get("client-fingerprint") or "chrome"}
            obj["tls"] = tls_dict

        # 归一化：clash network + ws-opts/grpc-opts/grpc → sing-box transport
        network = (obj.get("network") or "tcp").lower()
        if network != "tcp":
            transport: Dict[str, Any] = {"type": network}
            opts_key = network + "-opts"
            opts = obj.get(opts_key)
            if isinstance(opts, dict):
                for k, v in opts.items():
                    if k in ("headers",):
                        continue  # headers 单独处理（嵌套 dict）
                    if k in ("tls", "skip-cert-verify", "servername", "server_name", "Host"):
                        continue  # clash 专有字段不进 transport
                    transport[k] = v
                hdrs = opts.get("headers")
                if isinstance(hdrs, dict) and hdrs:
                    transport["headers"] = hdrs
                if network == "ws" and isinstance(opts.get("path"), str):
                    transport["path"] = opts["path"] or "/"
            # grpc 兼容：serviceName 可能直接在 grpc-opts 或顶层
            if network == "grpc" and not transport.get("service_name"):
                transport["service_name"] = obj.get("serviceName") or obj.get("service_name", "")
            obj["transport"] = transport
        # hy2 obfs 参数 → rawConfig 保留（config_manager 生成 outbound 时映射）
        if proto == "hysteria2":
            if obj.get("obfs-password"):
                obj["obfsPassword"] = obj["obfs-password"]
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

def import_nodes(sub_id: str, group: str, sub_name: str, nodes: List[Dict[str, Any]], stale: bool = False) -> Dict[str, Any]:
    """把解析出的节点导入 DB（对齐前端：按 server:port 去重、分组继承、随机 auth、subId 关联）。"""
    from db import random_auth, create_node_batch

    prepared: List[Dict[str, Any]] = []
    for pn in nodes:
        rc = pn.get("rawConfig") or {}
        user, passwd = random_auth(0)
        prepared.append({
            "id": db.new_node_id(),
            "name": pn.get("name", "未命名"),
            "protocol": pn.get("protocol", "shadowsocks"),
            "group": group,
            # 端口取 0 = 交给 create_node_batch 批内自动分配（52001 起递增），
            # 避免这里逐节点 get_next_available_port 拿到相同端口导致后续全 skip
            "port": 0,
            "segment": 52,
            "authUser": user,
            "authPass": passwd,
            "status": "offline",
            "ping": 0,
            "exitIp": "N/A",
            "upTraffic": 0,
            "downTraffic": 0,
            "rawConfig": rc,
            "subId": sub_id,
            "subName": sub_name,
            "stale": stale,
            "selected": False,
            "entryProto": "mixed",
            "ssPass": None,
        })
    return create_node_batch(prepared)


# ---------- 刷新 ----------

async def refresh_sub(sub: Dict[str, Any]) -> Dict[str, Any]:
    """拉取→解析→导入；失败用 last-good snapshot 兜底标 stale。"""
    sub_id = sub["id"]
    res = await fetch_subscription(sub["url"])
    if res["ok"]:
        nodes = parse_content(res["content"])
        if not nodes:
            _sub = db.update_sub(sub_id, {"last_error": "解析 0 个节点"})
            if not _sub:
                return {"id": sub_id, "ok": False, "count": 0, "stale": False, "imported": 0,
                        "error": "订阅已被删除"}
            return {"id": sub_id, "ok": False, "count": 0, "stale": False, "imported": 0,
                    "error": "解析 0 个节点"}
        imported = import_nodes(sub_id, sub.get("group", "订阅节点"), sub.get("name", ""), nodes, stale=False)
        # 订阅恢复正常：清除之前失败兜底标的 stale 警示（否则节点永久橙色"刷新失败"）
        db.unmark_nodes_stale_by_sub(sub_id)
        _sub = db.update_sub(sub_id, {
            "last_refresh": int(time.time() * 1000),
            "node_count": len(nodes),
            "last_error": None,
            "snapshot": json.dumps(nodes, ensure_ascii=False),
        })
        if not _sub:
            return {"id": sub_id, "ok": True, "count": len(nodes), "stale": False,
                    "imported": imported, "warning": "订阅元数据更新失败（已删除）"}
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
                imported = import_nodes(sub["id"], sub.get("group", "订阅节点"), sub.get("name", ""), nodes, stale=True)
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
