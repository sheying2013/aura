"""Fetch public subscriptions with DNS results pinned to each HTTP connection."""
import asyncio
import ipaddress
import os
import socket
import ssl
from urllib.parse import urljoin

import httpx

_USER_AGENT = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36"
_MAX_BYTES = 10 * 1024 * 1024
_TIMEOUT = 15.0
_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class _UnsafeURL(ValueError):
    pass


def _public_ip(value: str):
    # Scoped IPv6 addresses must not select an interface on the fetching host.
    if "%" in value:
        raise _UnsafeURL()
    address = ipaddress.ip_address(value)
    if not address.is_global or address.is_multicast:
        raise _UnsafeURL()
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        if not address.ipv4_mapped.is_global or address.ipv4_mapped.is_multicast:
            raise _UnsafeURL()
    return address


async def _resolve_public_url(value: str):
    try:
        logical = httpx.URL(value)
        if logical.scheme not in ("http", "https") or not logical.host:
            raise _UnsafeURL()
        if logical.username or logical.password:
            raise _UnsafeURL()
        host = logical.host
        try:
            address = ipaddress.ip_address(host)
        except ValueError:
            port = logical.port or (443 if logical.scheme == "https" else 80)
            answers = await asyncio.to_thread(
                socket.getaddrinfo, host, port, type=socket.SOCK_STREAM
            )
            if not answers:
                raise _UnsafeURL()
            # Validate every result before deduplicating; retries may only use
            # this snapshot, never a fresh hostname resolution.
            addresses = list(dict.fromkeys(
                str(_public_ip(answer[4][0])) for answer in answers
            ))
        else:
            addresses = [str(_public_ip(str(address)))]
        return logical.copy_with(fragment=None), addresses
    except (ValueError, httpx.InvalidURL, socket.gaierror, OSError) as exc:
        raise _UnsafeURL() from exc


def _deployment_proxy(scheme: str):
    # Select explicitly by the logical scheme. Keep trust_env=False so NO_PROXY
    # cannot bypass the chosen deployment exit for the pinned numeric target.
    for variable in (f"{scheme.upper()}_PROXY", f"{scheme}_proxy", "ALL_PROXY", "all_proxy"):
        value = os.environ.get(variable, "").strip()
        if value:
            return value
    return None


def _is_certificate_error(error: BaseException) -> bool:
    # HTTPX/httpcore wrap SSL errors as ConnectError. Inspect the chain so a
    # rejected certificate does not become permission to try another endpoint.
    seen = set()
    pending = [error]
    while pending:
        cause = pending.pop()
        if id(cause) in seen:
            continue
        seen.add(id(cause))
        if isinstance(cause, ssl.CertificateError):
            return True
        message = str(cause).upper()
        if "CERTIFICATE_VERIFY_FAILED" in message or "CERTIFICATE VERIFY FAILED" in message:
            return True
        pending.extend(item for item in (cause.__cause__, cause.__context__) if item is not None)
    return False


async def _fetch(url: str) -> dict:
    logical_value = url
    deadline = asyncio.get_running_loop().time() + _TIMEOUT
    for hop in range(_MAX_REDIRECTS + 1):
        logical, addresses = await _resolve_public_url(logical_value)
        # HTTPX generates the correct authority, including IPv6 brackets and
        # non-default ports, from the logical URL.
        host_header = httpx.Request("GET", logical).headers["Host"]
        # httpcore uses sni_hostname for both TLS SNI and certificate hostname
        # verification. The numeric URL alone would verify against the IP.
        extensions = {"sni_hostname": logical.raw_host.decode("ascii")}
        # One client per hop avoids pooling a TLS connection across different
        # logical hostnames which happen to resolve to the same IP.
        async with httpx.AsyncClient(
            follow_redirects=False, timeout=_TIMEOUT, trust_env=False,
            proxy=_deployment_proxy(logical.scheme),
        ) as client:
            for index, address in enumerate(addresses):
                remaining = deadline - asyncio.get_running_loop().time()
                if remaining <= 0:
                    raise TimeoutError()
                # Leave budget for alternate addresses when the first IP drops
                # packets. The outer timeout still bounds DNS/TLS/body/all hops.
                connect_timeout = min(3.0, remaining / (len(addresses) - index))
                request = client.build_request(
                    "GET", logical.copy_with(host=address),
                    headers={"User-Agent": _USER_AGENT, "Host": host_header,
                             "Accept-Encoding": "identity"},
                    extensions=extensions,
                    timeout=httpx.Timeout(_TIMEOUT, connect=connect_timeout),
                )
                try:
                    response = await client.send(request, stream=True)
                except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                    if _is_certificate_error(exc) or index == len(addresses) - 1:
                        raise
                    continue
                # Retry scope ends before reading the response: status errors,
                # read failures and body decoding errors never cause a fallback.
                try:
                    status = response.status_code
                    if status in _REDIRECT_STATUSES:
                        location = response.headers.get("location")
                        if not location:
                            return {"ok": False, "status": status, "error": "重定向缺少目标 URL"}
                        if hop == _MAX_REDIRECTS:
                            return {"ok": False, "status": status, "error": "订阅重定向超过 5 次"}
                        logical_value = urljoin(str(logical), location)
                        break
                    if status >= 300:
                        return {"ok": False, "status": status, "error": f"HTTP {status}"}
                    length = response.headers.get("content-length", "")
                    if length.isdecimal() and int(length) > _MAX_BYTES:
                        return {"ok": False, "status": status, "error": "订阅内容超过 10 MiB"}
                    content = bytearray()
                    # Count decoded bytes too, in case a server ignores identity and
                    # returns compressed content. Bound retained content before append.
                    async for chunk in response.aiter_bytes(chunk_size=64 * 1024):
                        if len(content) + len(chunk) > _MAX_BYTES:
                            return {"ok": False, "status": status, "error": "订阅内容超过 10 MiB"}
                        content.extend(chunk)
                    text = content.decode(response.encoding or "utf-8", errors="replace")
                    return {"ok": True, "status": status, "content": text}
                finally:
                    await response.aclose()
    raise AssertionError("unreachable redirect loop")


async def fetch_public_subscription(url: str) -> dict:
    """Return the legacy ok/status/content/error result without exposing URLs."""
    try:
        # Includes DNS, redirects and body reads, rather than only per-I/O timeouts.
        async with asyncio.timeout(_TIMEOUT):
            return await _fetch(url)
    except _UnsafeURL:
        return {"ok": False, "error": "仅允许公网 http/https 订阅 URL"}
    except (TimeoutError, httpx.TimeoutException):
        return {"ok": False, "error": "订阅请求超时"}
    except Exception:
        # Transport exception strings may contain tokens in paths/query strings.
        return {"ok": False, "error": "订阅请求失败"}
