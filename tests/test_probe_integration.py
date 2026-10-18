"""真实 socket 链路回归：本地起极简 SOCKS5 / HTTP 代理。

test_probe_regressions.py 用 FakeSocket 打桩验证协议字节，盖不到「真实 TCP + 真实
双向转发 + 真实响应流拼接」这一段；本文件补上：握手后必须按 RFC 1928 消费变长
BND.ADDR，否则后续 HTTP 流会错位。全部本地闭环（127.0.0.1），不依赖外网。
"""
import os
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import probe_ip


def _recv(conn, size):
    data = bytearray()
    while len(data) < size:
        chunk = conn.recv(size - len(data))
        if not chunk:
            raise OSError("peer closed")
        data.extend(chunk)
    return bytes(data)


def _pipe(a, b):
    """双向转发，任一端 EOF 即收工。"""
    socks = [a, b]
    try:
        while True:
            ready, _, broken = select.select(socks, [], socks, 5)
            if broken or not ready:
                return
            for src in ready:
                chunk = src.recv(4096)
                if not chunk:
                    return
                (b if src is a else a).sendall(chunk)
    except OSError:
        return


class _OriginServer:
    """返回固定 IP 的极简源站。"""

    def __init__(self, body=b"203.0.113.7\n"):
        def do_get(handler):
            handler.send_response(200)
            handler.send_header("Content-Length", str(len(body)))
            handler.end_headers()
            handler.wfile.write(body)

        handler_cls = type("_Handler", (BaseHTTPRequestHandler,), {
            "do_GET": do_get,
            "log_message": lambda *args, **kwargs: None,
        })
        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), handler_cls)
        self.port = self.httpd.server_address[1]
        self._thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.httpd.shutdown()
        self.httpd.server_close()


class _Socks5Server:
    """极简 SOCKS5（无认证）：回调 CONNECT 应答，再把连接转发到 connect_to。"""

    def __init__(self, connect_to, reply_rep=0x00):
        self.connect_to = connect_to
        self.reply_rep = reply_rep
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        upstream = None
        try:
            conn.settimeout(5)
            _, nmethods = _recv(conn, 2)
            _recv(conn, nmethods)
            conn.sendall(b"\x05\x00")
            header = _recv(conn, 4)
            atyp = header[3]
            if atyp == 0x01:
                _recv(conn, 4)
            elif atyp == 0x03:
                _recv(conn, _recv(conn, 1)[0])
            elif atyp == 0x04:
                _recv(conn, 16)
            else:
                return
            _recv(conn, 2)  # 目标端口
            if self.reply_rep:
                conn.sendall(b"\x05" + bytes([self.reply_rep]) + b"\x00\x01" + b"\x00" * 6)
                return
            # 故意用域名形态回 BND.ADDR：客户端不按 RFC 1928 读变长地址就会错位
            bnd = b"origin.test"
            conn.sendall(b"\x05\x00\x00\x03" + bytes([len(bnd)]) + bnd + (80).to_bytes(2, "big"))
            upstream = socket.create_connection(self.connect_to, timeout=5)
            _pipe(conn, upstream)
        except OSError:
            return
        finally:
            for item in (upstream, conn):
                if item is not None:
                    try:
                        item.close()
                    except OSError:
                        pass


class _HttpProxy:
    """极简 HTTP 代理：读完请求头就回固定 IP。"""

    def __init__(self, body=b"198.51.100.9\n"):
        self.body = body
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.port = self.sock.getsockname()[1]
        self._stop = threading.Event()

    def __enter__(self):
        threading.Thread(target=self._serve, daemon=True).start()
        return self

    def __exit__(self, *exc):
        self._stop.set()
        try:
            self.sock.close()
        except OSError:
            pass

    def _serve(self):
        self.sock.settimeout(0.5)
        while not self._stop.is_set():
            try:
                conn, _ = self.sock.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self._handle, args=(conn,), daemon=True).start()

    def _handle(self, conn):
        try:
            conn.settimeout(5)
            buf = b""
            while b"\r\n\r\n" not in buf:
                chunk = conn.recv(4096)
                if not chunk:
                    return
                buf += chunk
            head = b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(self.body)).encode()
            conn.sendall(head + b"\r\n\r\n" + self.body)
        except OSError:
            return
        finally:
            try:
                conn.close()
            except OSError:
                pass


def _node(protocol, port, **extra):
    node = {"protocol": protocol, "rawConfig": {"server": "127.0.0.1", "server_port": port}}
    node.update(extra)
    return node


def test_socks5_real_socket_roundtrip(monkeypatch):
    """真实握手 + 变长 BND.ADDR + 真实响应流 —— 打桩测试覆盖不到的整段链路。"""
    with _OriginServer() as origin, _Socks5Server(("127.0.0.1", origin.port)) as proxy:
        monkeypatch.setattr(probe_ip, "_TARGETS", ("origin.test",))
        assert probe_ip.fetch_exit_ip_sync(_node("socks5", proxy.port)) == "203.0.113.7"


def test_socks5_rejected_connect_returns_none(monkeypatch):
    """CONNECT 被拒（REP=0x05）应安静失败，不抛异常、不编造出口 IP。"""
    with _OriginServer() as origin, _Socks5Server(("127.0.0.1", origin.port), reply_rep=0x05) as proxy:
        monkeypatch.setattr(probe_ip, "_TARGETS", ("origin.test",))
        assert probe_ip.fetch_exit_ip_sync(_node("socks5", proxy.port)) is None


def test_http_proxy_real_socket_roundtrip(monkeypatch):
    with _HttpProxy() as proxy:
        monkeypatch.setattr(probe_ip, "_TARGETS", ("origin.test",))
        assert probe_ip.fetch_exit_ip_sync(_node("http", proxy.port)) == "198.51.100.9"


def test_probe_attempt_reports_which_stage_broke():
    """ss 入口 + ss 协议：两条路径都结构性不可用，原因必须写明断在哪一环。"""
    attempt = probe_ip.probe_attempt({"protocol": "ss", "entryProto": "ss", "port": 0})
    assert attempt.ip is None
    assert attempt.reason == "native_unsupported+inbound_disabled"


def test_diagnose_explains_silent_failure():
    ss_node = probe_ip.diagnose({"protocol": "ss", "entryProto": "ss", "port": 20001})
    assert "不支持直连探测" in ss_node
    assert "没有混合入站可兜底" in ss_node

    bad_port = probe_ip.diagnose({"protocol": "ss", "entryProto": "mixed", "port": 0})
    assert "混合入站端口无效" in bad_port

    usable = probe_ip.diagnose({"protocol": "socks5",
                                "rawConfig": {"server": "example.org", "server_port": 1080},
                                "entryProto": "mixed", "port": 20001})
    assert usable == ""


@pytest.mark.skipif(os.environ.get("AURA_REAL_NET_TEST") != "1",
                    reason="需要外网：AURA_REAL_NET_TEST=1 开启")
def test_real_public_probe_through_local_forwarder():
    """真实外网链路（经本地转发器）：验证 DNS 解析、跨网 TCP 与真实响应体。"""
    with _Socks5Server(("api.ipify.org", 80)) as proxy:
        ip = probe_ip.fetch_exit_ip_sync(_node("socks5", proxy.port))
    assert ip, "经本地转发器未取到公网出口 IP"
    assert not ip.startswith("127.")
