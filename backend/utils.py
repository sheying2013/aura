"""跨模块共享的纯函数（唯一实现，禁止各模块再复制同等逻辑）。"""
import ipaddress
from typing import Any


def safe_int(v: Any, default: int = 0) -> int:
    """安全转 int：订阅里的端口可能是 '443abc' 等脏串，int() 会抛 ValueError。

    失败返回 default，由调用方跳过该项，避免单个坏节点瘫痪整条链路。
    """
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def is_ip_address(s: str) -> bool:
    """判断字符串是否为 IP 地址（v4/v6），即非 hostname。"""
    try:
        ipaddress.ip_address(s)
        return True
    except (ValueError, TypeError):
        return False
