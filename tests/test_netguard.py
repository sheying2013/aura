"""netguard 回归：自引用出站识别与改写。

事故背景（2026-10-22 新加坡 arm-3）：58 个 socks5 节点的 server 全是 sg.lsp121.eu.org，
解析回本机公网 IP 168.107.71.181。sing-box 出站拨回自己 → 云 NAT hairpin 多一个 socket
和 conntrack，上游挂掉时半开连接不释放，fd 涨到 1875 把整机拖死。

这里锁定三条行为：指向本机自建端口要改写 127.0.0.1；命中本面板入站端口要判定为
回环自引用（不能改写，否则自己拨自己）；与本机无关的节点一个字节都不许动。
"""
from pathlib import Path
import sys
import time
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import netguard  # noqa: E402

SELF_IP = "10.0.0.87"
SELF_DOMAIN = "sg.lsp121.eu.org"


class NetguardTest(unittest.TestCase):
    def setUp(self):
        netguard.reset_cache()

    def tearDown(self):
        netguard.reset_cache()

    def _patch_self(self, local_port=True):
        return (
            patch.object(netguard, "interface_ips", lambda: frozenset({SELF_IP})),
            patch.object(netguard, "resolve",
                         lambda host, ttl=300: (SELF_IP,) if host == SELF_DOMAIN else ()),
            patch.object(netguard, "serve_local", lambda port, timeout=0.3: local_port),
        )

    def test_hairpin_rewritten_to_loopback(self):
        iface, dns, probe = self._patch_self()
        with iface, dns, probe:
            item = {"type": "socks", "server": SELF_DOMAIN, "server_port": 40324}
            kind, detail = netguard.apply_rewrite(item, {51000, 2080}, [])
            self.assertEqual(kind, netguard.HAIRPIN)
            self.assertEqual(item["server"], netguard.LOOPBACK)
            self.assertIn("40324", detail)

    def test_inbound_port_is_loop_and_untouched(self):
        iface, dns, probe = self._patch_self()
        with iface, dns, probe:
            item = {"type": "socks", "server": SELF_DOMAIN, "server_port": 2080}
            kind, _detail = netguard.apply_rewrite(item, {2080}, [])
            self.assertEqual(kind, netguard.LOOP)
            # 回环自引用不能改写：改写后 sing-box 会自己拨自己的入站，出站→入站→出站
            self.assertEqual(item["server"], SELF_DOMAIN)

    def test_port_not_served_locally_stays_untouched(self):
        iface, dns, probe = self._patch_self(local_port=False)
        with iface, dns, probe:
            item = {"type": "socks", "server": SELF_DOMAIN, "server_port": 40324}
            kind, _detail = netguard.apply_rewrite(item, set(), [])
            self.assertEqual(kind, "")
            self.assertEqual(item["server"], SELF_DOMAIN)

    def test_external_ip_never_touched(self):
        # 外部地址不该触发任何探测：serve_local 设为爆炸来证明它没被调用
        item = {"type": "shadowsocks", "server": "203.0.113.7", "server_port": 443}
        with patch.object(netguard, "serve_local", side_effect=AssertionError("不该探测")):
            kind, _detail = netguard.apply_rewrite(item, {51000}, [])
        self.assertEqual(kind, "")
        self.assertEqual(item["server"], "203.0.113.7")

    def test_unresolvable_host_is_safe(self):
        with patch.object(netguard, "interface_ips", lambda: frozenset({SELF_IP})), \
                patch.object(netguard, "serve_local", side_effect=AssertionError("不该探测")):
            kind, _detail = netguard.apply_rewrite(
                {"server": "no-such-host.invalid", "server_port": 443}, set(), [])
        self.assertEqual(kind, "")

    def test_self_ips_covers_declared_domain(self):
        with patch.object(netguard, "interface_ips", lambda: frozenset({SELF_IP})), \
                patch.object(netguard, "resolve",
                             lambda host, ttl=300: (SELF_IP,) if host == SELF_DOMAIN else ()):
            ips = netguard.self_ips([SELF_DOMAIN])
        self.assertIn(SELF_IP, ips)
        self.assertIn(netguard.LOOPBACK, ips)

    def test_self_domains_from_settings(self):
        domains = netguard.self_domains_from_settings(
            {"exportDomain": "sgp.zemeil.cyou"},
            [{"domain": "a.example.com"}, {"domain": ""}, None])
        self.assertEqual(domains, ["sgp.zemeil.cyou", "a.example.com"])

    def test_pass_budget_stops_new_lookups(self):
        """预算用尽后不再做任何 DNS/端口探测：留给接口的必须是不阻塞。"""
        netguard.begin_pass(0.001)
        time.sleep(0.01)
        with patch.object(netguard, "interface_ips", lambda: frozenset({SELF_IP})), \
                patch.object(netguard.socket, "getaddrinfo",
                             side_effect=AssertionError("超预算不该再解析")):
            kind, _detail = netguard.apply_rewrite(
                {"server": "slow.example.com", "server_port": 443}, set(), [])
        self.assertEqual(kind, "")

    def test_empty_inputs_do_not_raise(self):
        kind, detail = netguard.apply_rewrite({}, set(), [])
        self.assertEqual((kind, detail), ("", ""))
        self.assertEqual(netguard.classify("", 0), ("", ""))
        self.assertEqual(netguard.classify(SELF_DOMAIN, 70000), ("", ""))


if __name__ == "__main__":
    unittest.main()
