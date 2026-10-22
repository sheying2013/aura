"""本机地址识别与自引用（hairpin）出站改写。

事故背景（2026-10-22 新加坡 arm-3）：
58 个 socks5 节点的 server 全是 sg.lsp121.eu.org，该域名解析回本机公网 IP
168.107.71.181。sing-box 出站于是拨回自己的公网 IP，经云 NAT hairpin 绕一圈再进本机
代理端口（宿主上的 nodetap_arm64）。上游端口挂掉或池子打满时，半开连接长期不释放：
sing-box fd 涨到 1875、整机 load 224、sshd 起不了新会话（面板看着 200，机器实际失联）。

两层修法：
1. 生成配置时识别「出站目标就是本机」（本模块）：目标端口不是本面板入站端口时，把
   server 改写成 127.0.0.1 走回环——少一次云 NAT hairpin、省一半 socket 与 conntrack；
   目标端口正是本面板自己的入站端口时判定为回环自引用，由调用方跳过该节点（否则
   sing-box 出站→自己入站→再出站，无限套娃）。
2. 运行时 fd 看门狗在 scheduler._guard_loop（见 scheduler.py），兜住仍在泄漏的会话。

判定口径（三重条件，宁可不改写也不误改别人的节点）：
  ① 解析结果命中本机地址集合（本机网卡地址 ∪ 出口域名解析结果 ∪ 回环地址）；
  ② 该端口在本机 127.0.0.1 上可连（确实由本机服务承接）；
  ③ 该端口不是本面板的入站端口（否则是自引用回环，不改写而是跳过）。
任何一步异常都退化为「不改写」，绝不让配置生成失败。
"""
import ipaddress
import socket
import struct
import time
from typing import Any, Dict, Iterable, List, Sequence, Tuple

try:  # Linux/Unix 才有 ioctl 取网卡地址；无则退化为只认回环
    import fcntl
except ImportError:  # pragma: no cover - Windows 无此模块
    fcntl = None  # type: ignore[assignment]

LOOPBACK = "127.0.0.1"
SIOCGIFADDR = 0x8915

LOOP = "loop"        # 自引用回环：出站打到自己入站端口，必须跳过节点
HAIRPIN = "hairpin"  # 解析到本机但不是入站端口：改写 127.0.0.1

_SELF_TTL = 300.0    # 本机地址集合缓存（DNS 结果 + 网卡地址）
_PROBE_TTL = 60.0    # 端口本机可达性缓存
_PROBE_TIMEOUT = 0.3

_self_cache: Dict[str, Any] = {"key": None, "ips": frozenset(), "at": 0.0}
_dns_cache: Dict[str, Tuple[float, Tuple[str, ...]]] = {}
_probe_cache: Dict[int, Tuple[float, bool]] = {}
_pass_deadline = 0.0  # 单轮 build_config 的探测预算截止时刻（0 = 不限）


def begin_pass(budget: float = 3.0) -> None:
    """给一轮出站判定设时间预算。build_config 是同步函数且跑在事件循环线程里，
    上百个不同域名的 getaddrinfo 叠加会让接口明显变卡；超预算后本模块直接放弃
    未判定的节点（退化为「不改写」），宁可少优化也不拖住事件循环。budget<=0 = 不限。
    """
    global _pass_deadline
    _pass_deadline = (time.time() + budget) if budget and budget > 0 else 0.0


def _over_budget() -> bool:
    return bool(_pass_deadline) and time.time() > _pass_deadline


def reset_cache() -> None:
    """清空全部缓存（测试与网卡/域名变更后使用）。"""
    global _pass_deadline
    _pass_deadline = 0.0
    _self_cache.update({"key": None, "ips": frozenset(), "at": 0.0})
    _dns_cache.clear()
    _probe_cache.clear()


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False


def interface_ips() -> frozenset:
    """枚举本机 IPv4 网卡地址（macOS/无 ioctl 平台返回空集合，不影响主流程）。"""
    ips = set()
    if fcntl is None:
        return frozenset(ips)
    try:
        names = [name for _idx, name in socket.if_nameindex()]
    except OSError:
        return frozenset(ips)
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for name in names:
            try:
                req = struct.pack("256s", name[:15].encode())
                ips.add(socket.inet_ntoa(fcntl.ioctl(sock.fileno(), SIOCGIFADDR, req)[20:24]))
            except OSError:
                continue
    except OSError:
        pass
    finally:
        if sock is not None:
            sock.close()
    return frozenset(ips)


def resolve(host: str, ttl: float = _SELF_TTL) -> Tuple[str, ...]:
    """解析主机名（IP 字面量直接返回），带 TTL 缓存。失败返回空元组，绝不抛异常。"""
    host = (host or "").strip().lower()
    if not host:
        return ()
    if _is_ip(host):
        return (host,)
    now = time.time()
    hit = _dns_cache.get(host)
    if hit and now - hit[0] < ttl:
        return hit[1]
    if _over_budget():
        return ()
    try:
        infos = socket.getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        ips = tuple(sorted({info[4][0].split("%")[0] for info in infos if info[4]}))
    except Exception:
        ips = ()
    _dns_cache[host] = (now, ips)
    return ips


def self_ips(self_domains: Sequence[str] = (), refresh: bool = False) -> frozenset:
    """本机地址集合 = 网卡地址 ∪ 自报域名（面板出口域名/中转域名）解析结果 ∪ 回环。

    self_domains 里空值/坏域名一律跳过；解析失败不缓存，下次重试。
    """
    key = tuple(sorted({(d or "").strip().lower() for d in self_domains if d}))
    now = time.time()
    if not refresh and _self_cache.get("key") == key and now - float(_self_cache["at"]) < _SELF_TTL:
        return _self_cache["ips"]  # type: ignore[return-value]
    ips = set(interface_ips())
    ips.update({LOOPBACK, "::1"})
    for domain in key:
        ips.update(resolve(domain))
    result = frozenset(ips)
    _self_cache.update({"key": key, "ips": result, "at": now})
    return result


def serve_local(port: int, timeout: float = _PROBE_TIMEOUT) -> bool:
    """该端口是否由本机 127.0.0.1 承接（短超时 + TTL 缓存）。"""
    if not (1 <= int(port) <= 65535):
        return False
    now = time.time()
    hit = _probe_cache.get(int(port))
    if hit and now - hit[0] < _PROBE_TTL:
        return hit[1]
    if _over_budget():
        return False
    ok = False
    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        ok = sock.connect_ex((LOOPBACK, int(port))) == 0
    except Exception:
        ok = False
    finally:
        if sock is not None:
            sock.close()
    _probe_cache[int(port)] = (now, ok)
    return ok


def classify(server: str, server_port: int, inbound_ports: Iterable[int] = (),
             self_domains: Sequence[str] = ()) -> Tuple[str, str]:
    """判定一个出站目标是否指向本机。

    返回 (kind, detail)：
      (LOOP, 说明)      —— 命中本面板入站端口，调用方必须跳过该节点；
      (HAIRPIN, 说明)   —— 指向本机自建服务，调用方把 server 改成 127.0.0.1；
      ("", "")          —— 与本机无关或无法判定，保持原样。
    """
    server = (server or "").strip()
    port = int(server_port or 0)
    if not server or not (1 <= port <= 65535):
        return ("", "")
    if server == LOOPBACK or server == "::1":
        return ("", "")  # 已经是回环，无需处理
    resolved = resolve(server)
    if not resolved:
        return ("", "")
    own = self_ips(self_domains) & set(resolved)
    if not own:
        return ("", "")
    if port in {int(p) for p in inbound_ports if p}:
        return (LOOP, f"{server}:{port} 命中本面板入站端口，回环自引用")
    if not serve_local(port):
        return ("", "")  # 本机不承接该端口：可能是同域名下的另一台机器，保持原样
    return (HAIRPIN, f"{server}:{port} 解析为本机 {sorted(own)[0]}，出站改写 127.0.0.1 免 NAT hairpin")


def apply_rewrite(out_item: Dict[str, Any], inbound_ports: Iterable[int] = (),
                  self_domains: Sequence[str] = ()) -> Tuple[str, str]:
    """就地处理一个 outbound 字典：命中回环返回 LOOP（调用方丢弃），命中 hairpin 则改写 server。"""
    kind, detail = classify(out_item.get("server") or out_item.get("address") or "",
                            int(out_item.get("server_port") or 0),
                            inbound_ports, self_domains)
    if kind == HAIRPIN:
        out_item["server"] = LOOPBACK
    return kind, detail


def self_domains_from_settings(settings: Dict[str, Any],
                               relay_domains: Sequence[Dict[str, Any]] = ()) -> List[str]:
    """从系统设置里取出「代表本机身份」的域名：出口域名 + 各中转入口域名。"""
    domains: List[str] = []
    export_domain = str((settings or {}).get("exportDomain") or "").strip()
    if export_domain:
        domains.append(export_domain)
    for rd in relay_domains or ():
        domain = str((rd or {}).get("domain") or "").strip()
        if domain:
            domains.append(domain)
    return domains
