"""Offline coverage: DNS and HTTP/TLS connections are replaced by in-memory fakes."""
import asyncio
import gzip
import ipaddress
import os
import socket
import ssl
import unittest
from unittest.mock import patch

import httpcore
import httpx

from backend import subscription_fetch as fetcher

_REAL_CLIENT = httpx.AsyncClient


class ChunkStream(httpx.AsyncByteStream):
    def __init__(self, chunks):
        self.chunks = chunks
        self.closed = False
        self.reads = 0

    async def __aiter__(self):
        for chunk in self.chunks:
            self.reads += 1
            yield chunk

    async def aclose(self):
        self.closed = True


class SubscriptionFetchTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Tests never inherit the developer machine's real deployment proxies.
        self.environment = patch.dict(os.environ, {}, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)

    async def fetch(self, url, responses=None, answers=None, handler=None):
        self.requests = []
        self.clients = []
        self.dns_calls = []
        queued = iter(responses or [])

        def dns(host, port, **kwargs):
            self.dns_calls.append((host, port, kwargs))
            if callable(answers):
                ips = answers(host)
            else:
                ips = (answers or {}).get(host, ["8.8.8.8"])
            return [
                (socket.AF_INET6 if ":" in ip else socket.AF_INET,
                 socket.SOCK_STREAM, socket.IPPROTO_TCP, "", (ip, port))
                for ip in ips
            ]

        async def transport(request):
            # Any domain handed to HTTPX rather than a pinned numeric address fails.
            self.assertTrue(ipaddress.ip_address(request.url.host).is_global)
            self.requests.append(request)
            if handler:
                return await handler(request)
            return next(queued)

        def client(*args, **kwargs):
            self.clients.append(kwargs.copy())
            self.assertIs(kwargs.get("trust_env"), False)
            self.assertIs(kwargs.get("follow_redirects"), False)
            # An explicit proxy creates HTTPX proxy mounts even with a custom
            # transport. Capture it above, then remove it to stay fully offline.
            kwargs.pop("proxy", None)
            kwargs["transport"] = httpx.MockTransport(transport)
            return _REAL_CLIENT(*args, **kwargs)

        with patch.object(fetcher.socket, "getaddrinfo", side_effect=dns), \
             patch.object(fetcher.httpx, "AsyncClient", side_effect=client):
            return await fetcher.fetch_public_subscription(url)

    async def test_hostname_is_pinned_and_preserves_host_and_sni(self):
        result = await self.fetch("https://sub.example:8443/sub?token=secret", [httpx.Response(200, text="subscription")])
        self.assertEqual(result, {"ok": True, "status": 200, "content": "subscription"})
        request = self.requests[0]
        self.assertEqual(str(request.url), "https://8.8.8.8:8443/sub?token=secret")
        self.assertEqual(request.headers["Host"], "sub.example:8443")
        self.assertEqual(request.extensions["sni_hostname"], "sub.example")
        self.assertEqual(len(self.dns_calls), 1)
        self.assertEqual(self.dns_calls[0][1], 8443)

    async def test_deployment_proxy_is_explicit_by_logical_scheme(self):
        cases = [
            ("http", {"HTTP_PROXY": "http://http-proxy.example:3128", "HTTPS_PROXY": "http://https-proxy.example:3128", "ALL_PROXY": "http://all-proxy.example:3128"}, "http://http-proxy.example:3128"),
            ("https", {"HTTP_PROXY": "http://http-proxy.example:3128", "HTTPS_PROXY": "http://https-proxy.example:3128", "ALL_PROXY": "http://all-proxy.example:3128"}, "http://https-proxy.example:3128"),
            ("https", {"ALL_PROXY": "socks5://all-proxy.example:1080"}, "socks5://all-proxy.example:1080"),
            ("http", {"HTTP_PROXY": "", "ALL_PROXY": "http://all-proxy.example:3128"}, "http://all-proxy.example:3128"),
            ("https", {"https_proxy": "http://lowercase.example:3128"}, "http://lowercase.example:3128"),
            ("http", {"HTTP_PROXY": "", "http_proxy": "", "ALL_PROXY": "", "all_proxy": ""}, None),
            ("https", {"HTTP_PROXY": "http://http-only.example:3128"}, None),
        ]
        for scheme, environment, expected in cases:
            with self.subTest(scheme=scheme, environment=environment), patch.dict(os.environ, environment, clear=True):
                result = await self.fetch(f"{scheme}://sub.example/sub", [httpx.Response(200, text="OK")])
                self.assertTrue(result["ok"])
                self.assertEqual(self.clients[0]["proxy"], expected)
                self.assertIs(self.clients[0]["trust_env"], False)
                self.assertEqual(self.requests[0].url.host, "8.8.8.8")
                self.assertEqual(self.requests[0].headers["Host"], "sub.example")
                self.assertEqual(self.requests[0].extensions["sni_hostname"], "sub.example")

    async def test_no_proxy_does_not_bypass_explicit_deployment_exit(self):
        with patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy.example:3128", "NO_PROXY": "*", "no_proxy": "8.8.8.8"}):
            result = await self.fetch("https://sub.example/sub", [httpx.Response(200, text="OK")])
        self.assertTrue(result["ok"])
        self.assertEqual(self.clients[0]["proxy"], "http://proxy.example:3128")
        self.assertIs(self.clients[0]["trust_env"], False)

    async def test_redirect_reselects_proxy_for_logical_scheme(self):
        with patch.dict(os.environ, {"HTTP_PROXY": "http://http-proxy.example:3128", "HTTPS_PROXY": "http://https-proxy.example:3128"}):
            result = await self.fetch("http://sub.example/sub", [
                httpx.Response(302, headers={"Location": "https://secure.example/sub"}),
                httpx.Response(200, text="OK"),
            ])
        self.assertTrue(result["ok"])
        self.assertEqual([client["proxy"] for client in self.clients], ["http://http-proxy.example:3128", "http://https-proxy.example:3128"])
        self.assertEqual(self.requests[1].headers["Host"], "secure.example")
        self.assertEqual(self.requests[1].extensions["sni_hostname"], "secure.example")

    async def test_rebinding_cannot_change_connection_ip(self):
        calls = 0

        def rebinding(host):
            nonlocal calls
            calls += 1
            return ["8.8.8.8"] if calls == 1 else ["127.0.0.1"]

        result = await self.fetch("http://rebind.example:8080/sub", [httpx.Response(200, text="OK")], rebinding)
        self.assertTrue(result["ok"])
        self.assertEqual(calls, 1)
        self.assertEqual(self.requests[0].url.host, "8.8.8.8")

    async def test_ipv6_connect_timeout_falls_back_to_ipv4(self):
        async def handler(request):
            self.assertEqual(request.headers["Host"], "sub.example:8443")
            self.assertEqual(request.extensions["sni_hostname"], "sub.example")
            self.assertGreater(request.extensions["timeout"]["connect"], 0)
            self.assertLessEqual(request.extensions["timeout"]["connect"], 3.0)
            if ":" in request.url.host:
                raise httpx.ConnectTimeout("IPv6 blackhole", request=request)
            return httpx.Response(200, text="OK")
        result = await self.fetch("https://sub.example:8443/sub", answers={
            "sub.example": ["2606:4700:4700::1111", "8.8.8.8"]
        }, handler=handler)
        self.assertTrue(result["ok"])
        self.assertEqual([r.url.host for r in self.requests], ["2606:4700:4700::1111", "8.8.8.8"])
        self.assertEqual(len(self.dns_calls), 1)
        self.assertEqual(len(self.clients), 1)

    async def test_same_family_connect_error_falls_back_without_dns(self):
        async def handler(request):
            if request.url.host == "8.8.8.8":
                raise httpx.ConnectError("refused", request=request)
            return httpx.Response(200, text="OK")
        result = await self.fetch("http://sub.example/sub", answers={
            "sub.example": ["8.8.8.8", "8.8.4.4"]
        }, handler=handler)
        self.assertTrue(result["ok"])
        self.assertEqual([r.url.host for r in self.requests], ["8.8.8.8", "8.8.4.4"])
        self.assertEqual(len(self.dns_calls), 1)

    async def test_all_addresses_fail_and_duplicates_are_not_retried(self):
        async def handler(request):
            raise httpx.ConnectError("failed token=SECRET", request=request)
        result = await self.fetch("http://sub.example/sub?token=SECRET", answers={
            "sub.example": ["8.8.8.8", "8.8.8.8", "8.8.4.4", "8.8.4.4"]
        }, handler=handler)
        self.assertEqual(result, {"ok": False, "error": "订阅请求失败"})
        self.assertEqual([r.url.host for r in self.requests], ["8.8.8.8", "8.8.4.4"])
        self.assertEqual(len(self.dns_calls), 1)

    async def test_ipv6_addresses_deduplicated_after_normalization(self):
        async def handler(request):
            raise httpx.ConnectError("failed", request=request)
        await self.fetch("http://sub.example/sub", answers={
            "sub.example": ["2606:4700:4700::1111", "2606:4700:4700:0:0:0:0:1111"]
        }, handler=handler)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(len(self.dns_calls), 1)

    async def test_mixed_private_list_rejected_before_first_address_attempt(self):
        result = await self.fetch("http://sub.example/sub", answers={
            "sub.example": ["2606:4700:4700::1111", "8.8.8.8", "127.0.0.1"]
        })
        self.assertFalse(result["ok"])
        self.assertEqual(self.requests, [])
        self.assertEqual(len(self.dns_calls), 1)

    async def test_http_errors_do_not_retry_another_address(self):
        for status in (400, 500, 503):
            with self.subTest(status=status):
                result = await self.fetch("http://sub.example/sub", [httpx.Response(status)], {
                    "sub.example": ["8.8.8.8", "8.8.4.4"]
                })
                self.assertEqual(result["status"], status)
                self.assertEqual(len(self.requests), 1)

    async def test_certificate_errors_do_not_retry_another_address(self):
        for chained in (True, False):
            with self.subTest(chained=chained):
                async def handler(request):
                    if chained:
                        try:
                            raise ssl.SSLCertVerificationError(1, "certificate rejected")
                        except ssl.SSLCertVerificationError as exc:
                            raise httpx.ConnectError("TLS failed", request=request) from exc
                    raise httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed", request=request)
                result = await self.fetch("https://sub.example/sub", answers={
                    "sub.example": ["8.8.8.8", "8.8.4.4"]
                }, handler=handler)
                self.assertFalse(result["ok"])
                self.assertEqual(len(self.requests), 1)

    async def test_response_read_failures_do_not_retry_another_address(self):
        for error_type in (httpx.ReadError, httpx.ReadTimeout, httpx.ConnectError):
            with self.subTest(error_type=error_type):
                class BrokenStream(ChunkStream):
                    async def __aiter__(self):
                        yield b"partial"
                        raise error_type("body read failed token=SECRET")
                stream = BrokenStream([])
                result = await self.fetch("http://sub.example/sub", [httpx.Response(200, stream=stream)], {
                    "sub.example": ["8.8.8.8", "8.8.4.4"]
                })
                self.assertFalse(result["ok"])
                self.assertNotIn("SECRET", str(result))
                self.assertEqual(len(self.requests), 1)
                self.assertTrue(stream.closed)

    async def test_connect_budget_leaves_time_for_fallback(self):
        async def handler(request):
            if request.url.host == "8.8.8.8":
                budget = request.extensions["timeout"]["connect"]
                self.assertLess(budget, 0.1)
                await asyncio.sleep(budget)
                raise httpx.ConnectTimeout("first IP timed out", request=request)
            return httpx.Response(200, text="OK")
        with patch.object(fetcher, "_TIMEOUT", 0.2):
            result = await self.fetch("http://sub.example/sub", answers={
                "sub.example": ["8.8.8.8", "8.8.4.4"]
            }, handler=handler)
        self.assertTrue(result["ok"])
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(len(self.dns_calls), 1)

    async def test_dns_runs_in_thread(self):
        import threading
        caller = threading.get_ident()
        resolver_threads = []

        def answers(host):
            resolver_threads.append(threading.get_ident())
            return ["8.8.8.8"]

        await self.fetch("http://sub.example/sub", [httpx.Response(200, text="OK")], answers)
        self.assertNotEqual(resolver_threads, [caller])
        self.assertEqual(len(resolver_threads), 1)

    async def test_empty_or_mixed_private_dns_is_rejected(self):
        for ips in ([], ["8.8.8.8", "10.0.0.1"], ["8.8.8.8", "::1"], ["100.64.0.1"], ["169.254.169.254"]):
            with self.subTest(ips=ips):
                result = await self.fetch("http://sub.example/sub", answers={"sub.example": ips})
                self.assertFalse(result["ok"])
                self.assertEqual(self.requests, [])

    async def test_dns_error_is_sanitized(self):
        def answers(host):
            raise socket.gaierror("token=SECRET")
        result = await self.fetch("http://sub.example/sub?token=SECRET", answers=answers)
        self.assertFalse(result["ok"])
        self.assertNotIn("SECRET", str(result))
        self.assertEqual(self.requests, [])

    async def test_non_public_literal_or_bad_scheme_is_rejected(self):
        for url in (
            "http://127.0.0.1/sub", "http://10.0.0.1/sub", "http://[::1]/sub",
            "http://[::ffff:127.0.0.1]/sub", "http://[fe80::1%25en0]/sub",
            "http://100.64.0.1/sub", "http://224.0.0.1/sub",
            "file:///etc/passwd", "ftp://sub.example/sub", "/relative", "http://",
            "http://user:SECRET@sub.example/sub",
        ):
            with self.subTest(url=url):
                result = await self.fetch(url)
                self.assertFalse(result["ok"])
                self.assertEqual(self.requests, [])
                self.assertEqual(self.dns_calls, [])
                self.assertNotIn("SECRET", str(result))

    async def test_public_literal_skips_dns(self):
        result = await self.fetch("http://8.8.8.8/sub", [httpx.Response(200, text="OK")])
        self.assertTrue(result["ok"])
        self.assertEqual(self.dns_calls, [])
        self.assertEqual(self.requests[0].headers["Host"], "8.8.8.8")

    async def test_ipv6_dns_and_literal_authority(self):
        result = await self.fetch("https://sub.example:8443/sub", [httpx.Response(200, text="OK")], {"sub.example": ["2606:4700:4700::1111"]})
        self.assertTrue(result["ok"])
        self.assertEqual(str(self.requests[0].url), "https://[2606:4700:4700::1111]:8443/sub")
        self.assertEqual(self.requests[0].headers["Host"], "sub.example:8443")
        result = await self.fetch("https://[2606:4700:4700::1111]:8443/sub", [httpx.Response(200, text="OK")])
        self.assertTrue(result["ok"])
        self.assertEqual(self.dns_calls, [])
        self.assertEqual(self.requests[0].headers["Host"], "[2606:4700:4700::1111]:8443")
        self.assertEqual(self.requests[0].extensions["sni_hostname"], "2606:4700:4700::1111")

    async def test_idna_host_and_sni(self):
        result = await self.fetch("https://bücher.example/sub", [httpx.Response(200, text="OK")])
        self.assertTrue(result["ok"])
        self.assertEqual(self.requests[0].headers["Host"], "xn--bcher-kva.example")
        self.assertEqual(self.requests[0].extensions["sni_hostname"], "xn--bcher-kva.example")

    async def test_relative_redirect_uses_logical_url(self):
        result = await self.fetch("https://sub.example/base/start", [
            httpx.Response(302, headers={"Location": "../next?token=x"}),
            httpx.Response(200, text="OK"),
        ])
        self.assertTrue(result["ok"])
        self.assertEqual(str(self.requests[1].url), "https://8.8.8.8/next?token=x")
        self.assertEqual(self.requests[1].headers["Host"], "sub.example")
        self.assertEqual([call[0] for call in self.dns_calls], ["sub.example", "sub.example"])

    async def test_redirect_changes_host_and_sni_even_for_same_ip(self):
        result = await self.fetch("https://first.example/sub", [
            httpx.Response(302, headers={"Location": "//second.example:8443/next"}),
            httpx.Response(200, text="OK"),
        ])
        self.assertTrue(result["ok"])
        self.assertEqual(self.requests[1].headers["Host"], "second.example:8443")
        self.assertEqual(self.requests[1].extensions["sni_hostname"], "second.example")
        self.assertEqual(len(self.clients), 2)

    async def test_redirect_to_private_dns_or_literal_is_rejected(self):
        for location in ("http://private.example/sub", "http://127.0.0.1/sub"):
            result = await self.fetch("http://sub.example/start", [httpx.Response(302, headers={"Location": location})], {"private.example": ["10.0.0.1"]})
            self.assertFalse(result["ok"])
            self.assertEqual(len(self.requests), 1)

    async def test_same_host_redirect_revalidates_dns(self):
        calls = 0
        def answers(host):
            nonlocal calls
            calls += 1
            return ["8.8.8.8"] if calls == 1 else ["127.0.0.1"]
        result = await self.fetch("http://sub.example/sub", [httpx.Response(302, headers={"Location": "/next"})], answers)
        self.assertFalse(result["ok"])
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(calls, 2)

    async def test_five_redirects_allowed_sixth_rejected(self):
        redirects = [httpx.Response(302, headers={"Location": f"/hop{i}"}) for i in range(5)]
        result = await self.fetch("http://sub.example/sub", redirects + [httpx.Response(200, text="OK")])
        self.assertTrue(result["ok"])
        self.assertEqual(len(self.requests), 6)
        redirects = [httpx.Response(302, headers={"Location": f"/hop{i}"}) for i in range(6)]
        result = await self.fetch("http://sub.example/sub", redirects)
        self.assertFalse(result["ok"])
        self.assertIn("5", result["error"])
        self.assertEqual(len(self.requests), 6)

    async def test_missing_location_and_http_errors_fail(self):
        for status in (302, 304, 400, 500):
            result = await self.fetch("http://sub.example/sub", [httpx.Response(status)])
            self.assertFalse(result["ok"])
            self.assertEqual(result["status"], status)

    async def test_body_size_cap_closes_stream(self):
        stream = ChunkStream([b"a" * (64 * 1024), b"b" * (64 * 1024), b"should not be read"])
        with patch.object(fetcher, "_MAX_BYTES", 64 * 1024):
            result = await self.fetch("http://sub.example/sub", [httpx.Response(200, stream=stream)])
        self.assertFalse(result["ok"])
        self.assertTrue(stream.closed)
        self.assertEqual(stream.reads, 2)

    async def test_declared_oversize_body_not_read(self):
        stream = ChunkStream([b"not read"])
        result = await self.fetch("http://sub.example/sub", [httpx.Response(200, headers={"Content-Length": str(fetcher._MAX_BYTES + 1)}, stream=stream)])
        self.assertFalse(result["ok"])
        self.assertTrue(stream.closed)
        self.assertEqual(stream.reads, 0)

    async def test_size_boundary_and_charset(self):
        with patch.object(fetcher, "_MAX_BYTES", 2):
            result = await self.fetch("http://sub.example/sub", [httpx.Response(200, headers={"Content-Type": "text/plain; charset=iso-8859-1"}, stream=ChunkStream([b"\xe9x"]))])
        self.assertEqual(result["content"], "éx")

    async def test_decoded_size_limit_for_compressed_response(self):
        stream = ChunkStream([gzip.compress(b"x" * 65537)])
        with patch.object(fetcher, "_MAX_BYTES", 65536):
            result = await self.fetch("http://sub.example/sub", [httpx.Response(200, headers={"Content-Encoding": "gzip"}, stream=stream)])
        self.assertFalse(result["ok"])
        self.assertTrue(stream.closed)

    async def test_transport_error_never_exposes_url_secrets(self):
        async def handler(request):
            raise httpx.ConnectError("failed https://sub.example/sub?token=SECRET", request=request)
        result = await self.fetch("https://sub.example/sub?token=SECRET", handler=handler)
        self.assertEqual(result, {"ok": False, "error": "订阅请求失败"})

    async def test_total_timeout(self):
        async def handler(request):
            await asyncio.Event().wait()
        with patch.object(fetcher, "_TIMEOUT", 0.02):
            result = await self.fetch("http://sub.example/sub", handler=handler)
        self.assertEqual(result, {"ok": False, "error": "订阅请求超时"})

    async def test_real_httpcore_uses_logical_tls_verification_name(self):
        events = []
        class Wire(httpcore.AsyncNetworkStream):
            def __init__(self):
                self.response = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nOK"
            async def read(self, max_bytes, timeout=None):
                data, self.response = self.response[:max_bytes], self.response[max_bytes:]
                return data
            async def write(self, buffer, timeout=None):
                events.append(("write", buffer))
            async def aclose(self): pass
            def get_extra_info(self, info): return None
            async def start_tls(self, ssl_context, server_hostname=None, timeout=None):
                events.append(("tls", server_hostname, ssl_context.verify_mode, ssl_context.check_hostname))
                return self
        class Backend(httpcore.AsyncNetworkBackend):
            async def connect_tcp(self, host, port, **kwargs):
                events.append(("connect", host, port))
                return Wire()
        def dns(host, port, **kwargs):
            self.assertEqual(host, "sub.example")
            return [(socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("8.8.8.8", port))]
        def client(*args, **kwargs):
            transport = httpx.AsyncHTTPTransport()
            transport._pool._network_backend = Backend()
            return _REAL_CLIENT(*args, transport=transport, **kwargs)
        with patch.object(fetcher.socket, "getaddrinfo", side_effect=dns) as resolver, \
             patch.object(fetcher.httpx, "AsyncClient", side_effect=client):
            result = await fetcher.fetch_public_subscription("https://sub.example:8443/sub")
        self.assertTrue(result["ok"])
        self.assertEqual(resolver.call_count, 1)
        self.assertIn(("connect", "8.8.8.8", 8443), events)
        self.assertIn(("tls", "sub.example", ssl.CERT_REQUIRED, True), events)
        self.assertTrue(any(event[0] == "write" and b"Host: sub.example:8443\r\n" in event[1] for event in events))


if __name__ == "__main__":
    unittest.main()
