"""build_config 与 netguard 的集成：自引用节点必须在生成配置阶段就被处理。

对应 2026-10-22 新加坡 arm-3 事故：58 个 socks5 节点的 server 全解析回本机公网 IP。
其中 server_port 落在本面板入站端口的节点是回环自引用（出站→自己入站→再出站），
必须整节点跳过；其余自引用节点把 server 改成 127.0.0.1，少一跳云 NAT hairpin。
外部节点一个字节都不许动。
"""
from pathlib import Path
import sys

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
import config_manager  # noqa: E402
import db  # noqa: E402
import netguard  # noqa: E402

SELF_IP = "10.0.0.87"
SELF_DOMAIN = "sg.lsp121.eu.org"


def _node(name, port, server, server_port, protocol="socks5"):
    return {
        "id": name, "name": name, "protocol": protocol, "group": "家宽h",
        "port": port, "status": "online", "entryProto": "ss",
        "authUser": "u", "authPass": "p", "ssPass": "entry-pass",
        "rawConfig": {"type": "socks", "server": server, "server_port": server_port,
                      "username": "u", "password": "p"},
    }


@pytest.fixture
def self_host(monkeypatch):
    """把本机伪装成 10.0.0.87，自报域名解析到本机，且所有端口都由本机承接。"""
    netguard.reset_cache()
    monkeypatch.setattr(netguard, "interface_ips", lambda: frozenset({SELF_IP}))
    monkeypatch.setattr(netguard, "resolve",
                        lambda host, ttl=300: (SELF_IP,) if host == SELF_DOMAIN else ())
    monkeypatch.setattr(netguard, "serve_local", lambda port, timeout=0.3: True)
    yield
    netguard.reset_cache()


def test_build_config_rewrites_hairpin_and_skips_loop(monkeypatch, self_host):
    nodes = [
        _node("英国h-04", 51033, SELF_DOMAIN, 40324),   # 自引用，端口由本机 nodetap 承接
        _node("法国h-08", 51013, SELF_DOMAIN, 51033),   # server_port 正是另一个节点的入站端口 → 回环
        _node("外部节点", 51014, "203.0.113.7", 443),    # 与本机无关，必须原样保留
    ]
    monkeypatch.setattr(db, "list_nodes", lambda: nodes)
    monkeypatch.setattr(db, "list_relay_domains", lambda: [])
    monkeypatch.setattr(db, "get_setting",
                        lambda key, default=None: {"exportDomain": "sgp.zemeil.cyou",
                                                   "inboundPort": 2080})

    built = config_manager.build_config()
    outbounds = {out["tag"]: out for out in built["config"]["outbounds"]}

    hairpin_tag = config_manager.outbound_tag("socks5", 51033)
    assert outbounds[hairpin_tag]["server"] == netguard.LOOPBACK

    loop_tag = config_manager.outbound_tag("socks5", 51013)
    assert loop_tag not in outbounds, "回环自引用节点必须跳过，否则 sing-box 自己拨自己"
    assert any("回环自引用" in err["reason"] for err in built["errors"])

    external_tag = config_manager.outbound_tag("socks5", 51014)
    assert outbounds[external_tag]["server"] == "203.0.113.7"

    # 入站端口规划要覆盖全部节点，回环判定才准
    assert config_manager._plan_inbound_ports(nodes, [], {"inboundPort": 2080}) == {51033, 51013, 51014, 2080}
