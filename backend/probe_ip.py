"""出口 IP 探测：经节点自身代理（socks5/http）或本地 sing-box 入站查真实公网出口 IP。

从 scheduler 中独立出来，让调度器只保留编排职责，网络 I/O 细节集中在本模块。

不变量：任何路径都不得把入口 server 的地址当作出口 IP 返回——出口 IP 只能来自
经代理实际访问远端探测站点得到的响应体。
"""
import asyncio
import base64
import ipaddress
import re
import socket
from typing import Any, Dict, Optional, Tuple

import subs_proxy
from utils import safe_int

# 可不依赖本地 sing-box 入站、直接用协议原生拨号的代理类型
NATIVE_PROXY_PROTOS = frozenset({"socks5", "socks", "http"})

CONNECT_TIMEOUT = 6  # 单次连接超时（秒）
MAX_RESPONSE = 65536  # 响应体上限，防异常上游无限灌数据
MIN_BODY = 7  # 短 IPv4 串长度，够用即可提前结束读取

# 出口 IP 探测站点（按顺序取第一个可用结果）
_TARGETS: Tuple[str, ...] = ("api.ipify.org", "icanhazip.com")

_IPV4_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _recv_exact(sock: socket.socket, size: int) -> bytes:
    """读满 size 字节（SOCKS5 定长应答必须读净，否则污染后续 HTTP 流）。"""
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise OSError("SOCKS5 响应提前结束")
        data.extend(chunk)
    return bytes(data)


def _origin_request(host: str) -> bytes:
    """直连目标站点用的请求（经 SOCKS5 隧道时用）。"""
    return (f"GET / HTTP/1.0\r\nHost: {host}\r\n"
            "Connection: close\r\n\r\n").encode()


def _proxy_request(host: str, user: str, passwd: str) -> bytes:
    """HTTP 代理用的绝对 URI 请求，带可选 Basic 认证。"""
    lines = [f"GET http://{host}/ HTTP/1.0", f"Host: {host}", "Connection: close"]
    if user or passwd:
        cred = base64.b64encode(f"{user}:{passwd}".encode()).decode()
        lines.append(f"Proxy-Authorization: Basic {cred}")
    lines += ["", ""]
    return "\r\n".join(lines).encode()


def _read_ip(sock: socket.socket, request: bytes) -> Optional[str]:
    """发送请求、读取响应体并从中解析出合法 IP（socks5/http 两条路径共用）。"""
    sock.sendall(request)
    buf = b""
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        buf += chunk
        if len(buf) > MAX_RESPONSE:
            break
        if b"\r\n\r\n" in buf and len(buf.split(b"\r\n\r\n", 1)[1]) >= MIN_BODY:
            break

    _, sep, body = buf.partition(b"\r\n\r\n")
    if not sep:
        return None
    m = _IPV4_RE.search(body.strip().decode(errors="ignore"))
    if not m:
        return None
    candidate = m.group(1)
    try:
        ipaddress.ip_address(candidate)
    except ValueError:
        return None
    return candidate


def _socks5_handshake(sock: socket.socket, host: str, port: int, user: str, passwd: str) -> bool:
    """完成 SOCKS5 认证 + CONNECT，返回是否就绪。"""
    # 声明支持 0x00(无认证) 与 0x02(账号密码认证)
    sock.sendall(b"\x05\x02\x00\x02")
    method, chosen = _recv_exact(sock, 2)
    if method != 0x05:
        return False
    if chosen == 0x02:
        ub = (user or "").encode()
        pb = (passwd or "").encode()
        sock.sendall(b"\x01" + bytes([len(ub)]) + ub + bytes([len(pb)]) + pb)
        if _recv_exact(sock, 2)[1] != 0x00:
            return False
    elif chosen != 0x00:
        return False

    hb = host.encode()
    sock.sendall(b"\x05\x01\x00\x03" + bytes([len(hb)]) + hb + port.to_bytes(2, "big"))

    # 按 RFC 1928 消费完整 CONNECT 应答的变长地址部分
    hdr = _recv_exact(sock, 4)
    if hdr[1] != 0x00 or hdr[2] != 0x00:
        return False
    atyp = hdr[3]
    if atyp == 0x01:  # IPv4
        _recv_exact(sock, 6)
    elif atyp == 0x03:  # Domain
        _recv_exact(sock, _recv_exact(sock, 1)[0] + 2)
    elif atyp == 0x04:  # IPv6
        _recv_exact(sock, 18)
    else:
        return False
    return True


def _dial_socks5(host: str, port: int, user: str, passwd: str, target: str) -> Optional[str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((host, port))
        if not _socks5_handshake(sock, target, 80, user, passwd):
            return None
        return _read_ip(sock, _origin_request(target))
    except Exception:
        return None
    finally:
        _close(sock)


def _dial_http(host: str, port: int, user: str, passwd: str, target: str) -> Optional[str]:
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(CONNECT_TIMEOUT)
        sock.connect((host, port))
        return _read_ip(sock, _proxy_request(target, user, passwd))
    except Exception:
        return None
    finally:
        _close(sock)


def _close(sock: Optional[socket.socket]) -> None:
    if sock is None:
        return
    try:
        sock.close()
    except Exception:
        pass


def _probe_native(node: Dict[str, Any]) -> Optional[str]:
    """按节点原生代理协议直连探测（不经过本地 sing-box 入站）。"""
    proto = (node.get("protocol") or "").lower()
    if proto not in NATIVE_PROXY_PROTOS:
        return None
    endpoint = subs_proxy.proxy_endpoint(node)
    if not endpoint:
        return None
    dial = _dial_http if proto == "http" else _dial_socks5
    for target in _TARGETS:
        ip = dial(endpoint.host, endpoint.port, endpoint.username, endpoint.password, target)
        if ip:
            return ip
    return None


def _probe_inbound(node: Dict[str, Any]) -> Optional[str]:
    """经本地 sing-box mixed 入站探测（原生代理探测失败或不适用时的兜底）。"""
    port = safe_int(node.get("port"))
    if (node.get("entryProto") or "mixed") != "mixed" or not 1 <= port <= 65535:
        return None
    user = node.get("authUser") or "user"
    passwd = node.get("authPass") or "pass"
    for target in _TARGETS:
        ip = _dial_socks5("127.0.0.1", port, user, passwd, target)
        if ip:
            return ip
    return None


def fetch_exit_ip_sync(node: Dict[str, Any]) -> Optional[str]:
    """同步探测（阻塞，仅供 to_thread 调用）。"""
    return _probe_native(node) or _probe_inbound(node)


async def fetch_exit_ip(node: Dict[str, Any]) -> Optional[str]:
    """异步探测节点真实出口 IP：先按原生协议直连，失败再走本地入站兜底。"""
    return await asyncio.to_thread(fetch_exit_ip_sync, node)
