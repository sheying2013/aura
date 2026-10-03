"""订阅后端代理：安全拉取、服务端内容解析、last-good 快照、去重导入。

解析格式：Base64 列表 / Clash YAML(proxies:) / JSON(outbounds|proxies|数组) / 明文链接
协议：ss/vmess/vless/trojan/ssr/hysteria2/tuic
"""
import base64
import json
import re
import time
from typing import Any, Dict, List, Optional
from urllib.parse import unquote

import db
from subscription_fetch import fetch_public_subscription


# ---------- 拉取 ----------

async def fetch_subscription(url: str) -> Dict[str, Any]:
    return await fetch_public_subscription(url)


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
                # SIP002: method:pass@host:port[?plugin=...]
                cred, hostport = body.rsplit("@", 1)
                # 剥离端口后的查询串（?plugin=...），否则 int(port) 会崩 → 节点被静默丢弃
                if "?" in hostport:
                    hostport = hostport.split("?", 1)[0]
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
                # 名字可能嵌在 base64 载荷内部（如 "...#ss-Test"），外部剥离不到 → 解码后切出
                frag = ""
                di = dec.find("#")
                if di != -1:
                    frag = dec[di + 1:]
                    dec = dec[:di]
                m = re.match(r"^([^:]+):([^@]+)@([^:]+):(\d+)$", dec)
                if not m:
                    return None
                return {
                    "name": name or frag or f"ss-{m.group(3)}", "protocol": "shadowsocks",
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
                # P2-10：vless/trojan 无凭据（cred 为空）→ 跳过该行（垃圾 uuid 连不通只会迷惑用户）
                if not cred or not hostport:
                    return None
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
        # socks5:// / http:// — user:pass@host:port（可省略认证）
        for prefix, proto, cfg_type in (("socks5://", "socks5", "socks"),
                                        ("http://", "http", "http")):
            if line.startswith(prefix):
                body = line[len(prefix):]
                cred, sep, hostport = body.rpartition("@")
                hp = hostport.rsplit(":", 1)
                if len(hp) != 2:
                    return None
                rc = {"server": hp[0], "server_port": int(hp[1])}
                if sep:
                    u, _, p = cred.partition(":")
                    if u:
                        rc["username"] = u
                        rc["password"] = p
                return {
                    "name": name or f"{proto}-{hp[0]}", "protocol": proto,
                    "rawConfig": rc,
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

def import_nodes(sub_id: str, group: str, sub_name: str, nodes: List[Dict[str, Any]], stale: bool = False,
                 update_existing: bool = False) -> Dict[str, Any]:
    """把解析出的节点导入 DB（对齐前端：按 server:port 去重、分组继承、随机 auth、subId 关联）。

    update_existing=True（订阅刷新路径）：同 subId 已存在节点原地更新（P1-3）。
    """
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
    return create_node_batch(prepared, update_existing_sub=update_existing)


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
        imported = import_nodes(sub_id, sub.get("group", "订阅节点"), sub.get("name", ""), nodes, stale=False,
                                update_existing=True)
        # 订阅恢复正常：清除之前失败兜底标的 stale 警示（否则节点永久橙色"刷新失败"）
        db.unmark_nodes_stale_by_sub(sub_id)
        current_sub = db.get_sub(sub_id) or sub
        needs_apply = (imported["created"] > 0 or imported["updated"] > 0 or
                       bool(current_sub.get("pendingApply")))
        # 新增/上游变更先持久化 pending_apply；配置应用成功后才清除，防止失败后相同内容被跳过。
        _sub = db.update_sub(sub_id, {
            "last_refresh": int(time.time() * 1000),
            "node_count": len(nodes),
            "snapshot": json.dumps(nodes, ensure_ascii=False),
            "pending_apply": 1 if needs_apply else 0,
        })
        if not _sub:
            return {"id": sub_id, "ok": False, "count": len(nodes), "stale": False,
                    "imported": imported["created"], "updated": imported["updated"],
                    "error": "订阅元数据更新失败（已删除）"}
        if needs_apply:
            apply_error = None
            try:
                import config_manager
                applied = await config_manager.apply_config()
                if not isinstance(applied, dict) or not applied.get("ok"):
                    apply_error = (applied or {}).get("message", "配置应用失败") if isinstance(applied, dict) else "配置应用失败"
            except Exception as exc:
                apply_error = str(exc) or "配置应用异常"
            if apply_error:
                db.update_sub(sub_id, {"pending_apply": 1, "last_error": f"配置应用失败: {apply_error}"})
                return {"id": sub_id, "ok": False, "count": len(nodes), "stale": False,
                        "degraded": True, "imported": imported["created"],
                        "updated": imported["updated"], "error": f"配置应用失败: {apply_error}"}
            db.update_sub(sub_id, {"pending_apply": 0, "last_error": None})
        else:
            db.update_sub(sub_id, {"last_error": None})
        return {"id": sub_id, "ok": True, "count": len(nodes), "stale": False,
                "imported": imported["created"], "updated": imported["updated"], "error": None}

    # list_subs 不暴露快照；失败时补读持久化 last-good，避免批量/定时刷新丢失降级状态。
    current_sub = db.get_sub(sub_id)
    snap = current_sub.get("snapshot") if current_sub else None
    if snap:
        try:
            nodes = json.loads(snap)
            if isinstance(nodes, list) and nodes:
                # 已有节点继续使用 last-good，不重导入、更不覆盖本地配置。
                db.mark_nodes_stale_by_sub(sub_id)
                db.update_sub(sub_id, {"last_error": res.get("error")})
                return {"id": sub_id, "ok": False, "count": len(nodes), "stale": True,
                        "degraded": True, "imported": 0, "error": res.get("error")}
        except (TypeError, ValueError):
            pass
    db.update_sub(sub_id, {"last_error": res.get("error")})
    return {"id": sub_id, "ok": False, "count": 0, "stale": False, "imported": 0, "error": res.get("error")}


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
