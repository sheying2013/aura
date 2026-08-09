"""IP 归属地 + 纯净度情报模块。

数据源：
- ipinfo.io：归属地（country/region/city/org），免费 token 5 万次/月
- api.ipapi.is：数据中心/代理/VPN/Tor/滥用判断（is_datacenter 等），免费 1000 次/天
- 24h 缓存控量，任一源失败降级（不阻塞主流程）

返回字段与前端约定：exitCountry/exitFlag/exitCity/exitType/exitScore
- exitType: hosting(数据中心) / residential(住宅) / proxy(代理机场) / unknown
- exitScore: 0-100，纯净住宅 100，数据中心 ~40，VPN/代理/Tor ~30，滥用 ~10
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

try:
    import httpx
except Exception:  # pragma: no cover
    httpx = None

# 国家代码 → 中文名（ISO 3166 两字母；GB=英国，HK/TW/MO=中国）
COUNTRY_CN: Dict[str, str] = {
    "US": "美国", "JP": "日本", "KR": "韩国", "HK": "中国香港", "TW": "中国台湾",
    "SG": "新加坡", "DE": "德国", "FR": "法国", "GB": "英国", "NL": "荷兰",
    "CA": "加拿大", "AU": "澳大利亚", "RU": "俄罗斯", "CN": "中国大陆", "UA": "乌克兰",
    "MY": "马来西亚", "TH": "泰国", "VN": "越南", "IN": "印度", "BR": "巴西",
    "TR": "土耳其", "PL": "波兰", "RO": "罗马尼亚", "BG": "保加利亚", "CZ": "捷克",
    "ES": "西班牙", "IT": "意大利", "SE": "瑞典", "CH": "瑞士", "BE": "比利时",
    "IE": "爱尔兰", "FI": "芬兰", "NO": "挪威", "DK": "丹麦", "IL": "以色列",
    "AE": "阿联酋", "ZA": "南非", "MX": "墨西哥", "AR": "阿根廷", "NZ": "新西兰",
    "PT": "葡萄牙", "GR": "希腊", "AT": "奥地利", "HU": "匈牙利", "PH": "菲律宾",
    "ID": "印度尼西亚", "MO": "中国澳门", "PA": "巴拿马", "KZ": "哈萨克斯坦",
    "LT": "立陶宛", "LV": "拉脱维亚", "EE": "爱沙尼亚", "LU": "卢森堡", "CY": "塞浦路斯",
    "MT": "马耳他", "IS": "冰岛", "PK": "巴基斯坦", "BD": "孟加拉", "NG": "尼日利亚",
    "EG": "埃及", "SA": "沙特阿拉伯", "QA": "卡塔尔", "KW": "科威特",
}

# 国家代码 → 国旗 emoji（区域指示符计算）
_FLAG_OFFSET = 0x1F1E6 - ord("A")


def country_flag(cc: str) -> str:
    if not cc or len(cc) != 2:
        return ""
    cc = cc.upper()
    try:
        return chr(ord(cc[0]) + _FLAG_OFFSET) + chr(ord(cc[1]) + _FLAG_OFFSET)
    except Exception:
        return ""


def country_cn(cc: Optional[str]) -> str:
    if not cc:
        return ""
    return COUNTRY_CN.get(cc.upper(), cc.upper())


# ---------- 缓存（IP → 情报 dict，24h） ----------
_cache: Dict[str, Dict[str, Any]] = {}
_CACHE_TTL = 24 * 3600


def _cached(ip: str) -> Optional[Dict[str, Any]]:
    ent = _cache.get(ip)
    if not ent:
        return None
    if time.time() - ent["ts"] > _CACHE_TTL:
        _cache.pop(ip, None)
        return None
    return ent["data"]


def _store(ip: str, data: Dict[str, Any]) -> None:
    _cache[ip] = {"ts": time.time(), "data": data}
    if len(_cache) > 5000:  # LRU 淘汰最旧 20%（防缓存雪崩，不再 .clear() 全清）
        oldest = sorted(_cache, key=lambda k: _cache[k]["ts"])[:1000]
        for k in oldest:
            del _cache[k]


# ---------- 数据源查询 ----------

def _fetch(url: str, timeout: float = 4.0) -> Optional[Dict[str, Any]]:
    if httpx is None:
        return None
    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=True)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


def _query_ipinfo(ip: str) -> Optional[Dict[str, Any]]:
    """ipinfo.io 归属地。免费档返回 country/region/city/org。"""
    return _fetch(f"https://ipinfo.io/{ip}/json")


def _query_ipapis(ip: str) -> Optional[Dict[str, Any]]:
    """ipapi.is 数据中心/代理判断。sg 镜像国内低延迟。"""
    return _fetch(f"https://sg.ipapi.is/?q={ip}")


# ---------- 评分 ----------

def _score(ipapis: Optional[Dict[str, Any]]) -> int:
    if not ipapis:
        return 0  # 未知不评分
    if ipapis.get("is_bogon"):
        return 0
    if ipapis.get("is_abuser"):
        return 10
    if ipapis.get("is_datacenter"):
        return 40
    if ipapis.get("is_vpn") or ipapis.get("is_proxy") or ipapis.get("is_tor"):
        return 30
    return 100  # 纯净住宅


def _ip_type(ipapis: Optional[Dict[str, Any]]) -> str:
    if not ipapis:
        return "unknown"
    if ipapis.get("is_bogon"):
        return "unknown"
    if ipapis.get("is_datacenter"):
        return "hosting"
    if ipapis.get("is_vpn") or ipapis.get("is_proxy") or ipapis.get("is_tor"):
        return "proxy"
    if ipapis.get("is_abuser"):
        return "hosting"
    return "residential"


# ---------- 对外接口 ----------

def lookup(ip: str) -> Dict[str, Any]:
    """查 IP 情报并缓存。任一源失败降级，不抛异常。"""
    if not ip or ip == "N/A" or ip == "1.1.1.1":
        return {"exitIp": ip}
    hit = _cached(ip)
    if hit is not None:
        return hit

    result: Dict[str, Any] = {"exitIp": ip}
    info = _query_ipinfo(ip)
    ipapis = _query_ipapis(ip)

    cc = ""
    city = ""
    org = ""
    asn = ""
    if info:
        cc = (info.get("country") or "").upper()
        city = info.get("city") or ""
        org = info.get("org") or ""
        if org and " " in org:
            asn = org.split(" ", 1)[0]
    result["exitCountry"] = country_cn(cc) if cc else ""
    result["exitFlag"] = country_flag(cc) if cc else ""
    result["exitCity"] = city
    result["exitType"] = _ip_type(ipapis)
    result["exitScore"] = _score(ipapis)
    result["exitOrg"] = org
    result["exitAsn"] = asn

    _store(ip, result)
    return result


def lookup_batch(ips) -> Dict[str, Dict[str, Any]]:
    """批量查 IP 情报（逐 IP，独立降级）。"""
    return {ip: lookup(ip) for ip in ips}


# ---------- ping0.cc 增强（风控值/原生IP，经节点代理） ----------

_PING0_TTL = 7 * 24 * 3600  # ping0 数据变化慢，7 天缓存
_ping0_cache: Dict[str, Dict[str, Any]] = {}


def _parse_ping0(body: str) -> Dict[str, Any]:
    """从 ping0.cc HTML 提取：风控值 / IP 类型 / 原生IP / 适用场景。"""
    import re
    out: Dict[str, Any] = {}
    m = re.search(r'riskcurrent.*?value">(\d+)%</span><span class="lab">\s*([^<]+)', body, re.S)
    if m:
        out["exitRisk"] = int(m.group(1))
        out["exitRiskLabel"] = m.group(2).strip()
    m2 = re.search(r'line-iptype.*?content">(.*?)</div>', body, re.S)
    if m2:
        t = re.sub(r'<[^>]+>', '|', m2.group(1))
        t = re.sub(r'\|+', '|', t).strip('|').strip()
        if t:
            out["exitIpType"] = t[:40]
    m3 = re.search(r'line-nativeip.*?content">(.*?)</div>', body, re.S)
    if m3:
        t3 = re.sub(r'<[^>]+>', '', m3.group(1)).strip()
        if t3:
            out["exitNativeIp"] = t3[:20]
    return out


def _fetch_ping0_via_proxy(ip: str, proxy_url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """经 HTTP 代理访问 ping0.cc。socks5 代理需 pysocks；这里用 http 代理（mixed inbound 同时提供 http）。"""
    try:
        import urllib.request
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        req = urllib.request.Request(f"https://ping0.cc/ip/{ip}",
                                     headers={"User-Agent": "Mozilla/5.0"})
        body = opener.open(req, timeout=timeout).read().decode("utf-8", errors="replace")
        # 被 Cloudflare 风控挡时返回验证页（<5KB 且含 turnstile）
        if len(body) < 5000 or "turnstile" in body.lower():
            return None
        return _parse_ping0(body)
    except Exception:
        return None


def lookup_ping0(ip: str, nodes) -> Dict[str, Any]:
    """经节点代理查 ping0.cc 风控情报，多节点重试。失败返回空 dict。"""
    if not ip or not nodes:
        return {}
    ent = _ping0_cache.get(ip)
    if ent and time.time() - ent["ts"] < _PING0_TTL:
        return ent["data"]
    for n in nodes:
        port = n.get("port")
        user = n.get("authUser") or "user"
        passwd = n.get("authPass") or "pass"
        proxy = f"http://{user}:{passwd}@127.0.0.1:{port}"
        data = _fetch_ping0_via_proxy(ip, proxy)
        if data:
            _ping0_cache[ip] = {"ts": time.time(), "data": data}
            if len(_ping0_cache) > 2000:  # LRU 淘汰最旧 20%
                oldest = sorted(_ping0_cache, key=lambda k: _ping0_cache[k]["ts"])[:400]
                for k in oldest:
                    del _ping0_cache[k]
            return data
    return {}


# ---------- IPPure 增强（fraudScore/是否住宅，经节点代理） ----------

_IPPURE_TTL = 7 * 24 * 3600
_ippure_cache: Dict[str, Dict[str, Any]] = {}


def _fetch_ippure_via_proxy(proxy_url: str, timeout: float = 10.0) -> Optional[Dict[str, Any]]:
    """经 HTTP 代理调 my.ippure.com/v1/info（返回调用方 IP 情报）。"""
    try:
        import urllib.request
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({"http": proxy_url, "https": proxy_url}))
        req = urllib.request.Request("https://my.ippure.com/v1/info",
                                     headers={"User-Agent": "Mozilla/5.0"})
        body = opener.open(req, timeout=timeout).read().decode("utf-8", errors="replace")
        import json
        d = json.loads(body)
        if not isinstance(d, dict):
            return None
        return d
    except Exception:
        return None


def _parse_ippure(d: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    fs = d.get("fraudScore")
    if isinstance(fs, (int, float)):
        out["exitRisk"] = int(fs)  # 与 ping0 风控值同字段：越低越纯净
    out["exitResidential"] = bool(d.get("isResidential"))
    cc = (d.get("countryCode") or "").upper()
    if cc and len(cc) == 2:
        out["exitCountry"] = country_cn(cc)
        out["exitFlag"] = country_flag(cc)
    if d.get("city"):
        out["exitCity"] = d["city"]
    if d.get("asn"):
        out["exitAsn"] = f"AS{d['asn']}"
    return out


def lookup_ippure(nodes) -> Dict[str, Any]:
    """经节点代理查 IPPure 出口情报（fraudScore/住宅性）。返回调用方（节点出口）IP 的数据。"""
    if not nodes:
        return {}
    # 任意节点代理都可查（返回的是该节点的出口 IP），逐个尝试直到成功
    for n in nodes:
        port = n.get("port")
        user = n.get("authUser") or "user"
        passwd = n.get("authPass") or "pass"
        proxy = f"http://{user}:{passwd}@127.0.0.1:{port}"
        d = _fetch_ippure_via_proxy(proxy)
        if not d:
            continue
        ip = d.get("ip")
        if not ip:
            continue
        ent = _ippure_cache.get(ip)
        if ent and time.time() - ent["ts"] < _IPPURE_TTL:
            data = ent["data"]
        else:
            data = _parse_ippure(d)
            data["exitIp"] = ip
            _ippure_cache[ip] = {"ts": time.time(), "data": data}
            if len(_ippure_cache) > 2000:  # LRU 淘汰最旧 20%
                oldest = sorted(_ippure_cache, key=lambda k: _ippure_cache[k]["ts"])[:400]
                for k in oldest:
                    del _ippure_cache[k]
        return data
    return {}
