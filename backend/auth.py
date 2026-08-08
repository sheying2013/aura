"""认证模块：密码哈希、token 签发/校验、首次改密强制。

安全要点：
- 密码用 PBKDF2-SHA256 加盐哈希（非明文/非裸哈希）
- token 用 secrets.token_hex 随机生成，服务端存 SHA256(token) 防泄漏
- 登录失败延迟（防爆破），失败计数暂存在内存
- 默认密码 admin，首次登录强制改密（password_change_required）
"""
import asyncio
import hashlib
import hmac
import secrets
import time

import db
import panel_config

TOKEN_TTL = 7 * 24 * 60 * 60  # 7 天
FAIL_LOCKOUT_SECONDS = 5  # 失败后延迟

# 内存 token 缓存: token_hash -> {created_at, exp_at}
_tokens: dict = {}
# 失败计数: ip -> [timestamps]
_failures: dict = {}


def get_username() -> str:
    """当前面板登录用户名（默认 admin，可由 aura CLI / panel.conf 修改）。"""
    return panel_config.get("username") or "admin"


def hash_password(password: str, salt: str = "") -> str:
    """PBKDF2-SHA256 哈希。salt 为空时自动生成（返回 salt$hash）。"""
    if not salt:
        salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100_000)
    return f"{salt}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt, h = stored.split("$", 1)
        return hmac.compare_digest(hash_password(password, salt), stored)
    except Exception:
        return False


def _get_auth() -> dict:
    auth = db.get_setting("auth", {}) or {}
    if not auth.get("password_hash"):
        # 默认密码 admin，首次使用需改密
        auth = {
            "password_hash": hash_password("admin"),
            "password_change_required": True,
            "created_at": int(time.time() * 1000),
        }
        db.set_setting("auth", auth)
    return auth


def _record_failure(key: str) -> None:
    now = time.time()
    _failures.setdefault(key, []).append(now)
    _failures[key] = [t for t in _failures[key] if now - t < 60]
    # 防内存无限增长
    if len(_failures) > 1000:
        _failures.clear()


def is_rate_limited(key: str) -> bool:
    """60 秒内 >10 次失败则限流（返回 True 表示需等待）。"""
    now = time.time()
    recent = [t for t in _failures.get(key, []) if now - t < 60]
    if len(recent) >= 10:
        return True
    # 最近失败后强制延迟
    if recent:
        return now - recent[-1] < FAIL_LOCKOUT_SECONDS
    return False


async def login(username: str, password: str, client_ip: str = "") -> dict:
    """验证登录。成功返回 token + 是否需改密；失败返回错误。"""
    key = client_ip or "unknown"
    if is_rate_limited(key):
        return {"ok": False, "error": "尝试过于频繁，请稍后再试"}

    auth = _get_auth()
    # 用户名可从面板配置修改（默认 admin，单用户面板）
    if username != get_username():
        _record_failure(key)
        await asyncio.sleep(FAIL_LOCKOUT_SECONDS)
        return {"ok": False, "error": "用户名或密码错误"}

    if not verify_password(password, auth.get("password_hash", "")):
        _record_failure(key)
        await asyncio.sleep(FAIL_LOCKOUT_SECONDS)
        return {"ok": False, "error": "用户名或密码错误"}

    # 成功：签发 token
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    _tokens[token_hash] = {"created_at": now, "exp_at": now + TOKEN_TTL}
    # 清理过期 token
    for th in [k for k, v in _tokens.items() if v["exp_at"] < now]:
        del _tokens[th]
    return {
        "ok": True,
        "token": token,
        "passwordChangeRequired": bool(auth.get("password_change_required", False)),
    }


def verify_token(token: str) -> bool:
    if not token:
        return False
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    entry = _tokens.get(token_hash)
    if not entry:
        return False
    if entry["exp_at"] < time.time():
        del _tokens[token_hash]
        return False
    return True


def change_password(old_password: str, new_password: str) -> dict:
    """修改密码。校验旧密码 + 新密码强度。成功清首次改密标记，签发新 token。"""
    auth = _get_auth()
    if not verify_password(old_password, auth.get("password_hash", "")):
        return {"ok": False, "error": "旧密码错误"}
    if len(new_password) < 6:
        return {"ok": False, "error": "新密码至少 6 位"}
    if new_password == old_password:
        return {"ok": False, "error": "新密码不能与旧密码相同"}
    auth["password_hash"] = hash_password(new_password)
    auth["password_change_required"] = False
    auth["changed_at"] = int(time.time() * 1000)
    db.set_setting("auth", auth)
    # 改密后旧 token 全部失效，签发新 token 保持当前会话
    _tokens.clear()
    token = secrets.token_hex(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    now = time.time()
    _tokens[token_hash] = {"created_at": now, "exp_at": now + TOKEN_TTL}
    return {"ok": True, "message": "密码修改成功", "token": token}


def is_password_change_required() -> bool:
    return bool((db.get_setting("auth", {}) or {}).get("password_change_required", False))


def logout_token(token: str) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    _tokens.pop(token_hash, None)
