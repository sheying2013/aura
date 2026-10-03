"""认证并发回归测试；使用临时 SQLite，不触碰项目 data/panel.db。"""
import asyncio
import pathlib
import sys
import threading
from concurrent.futures import ThreadPoolExecutor
from contextlib import nullcontext

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "backend"))

import auth  # noqa: E402
import db  # noqa: E402


@pytest.fixture
def isolated_auth_db(tmp_path, monkeypatch):
    """给 auth/db 一个每测独立的临时 settings 数据库。"""
    db_path = tmp_path / "panel.db"
    monkeypatch.setattr(db, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(db, "DB_PATH", str(db_path))
    monkeypatch.setattr(db, "_conn", None)
    db.init_db()
    monkeypatch.setattr(auth, "get_username", lambda: "admin")
    with auth._auth_lock:
        auth._tokens.clear()
        auth._failures.clear()
    yield
    with auth._auth_lock:
        auth._tokens.clear()
        auth._failures.clear()
    if db._conn is not None:
        db._conn.close()
        db._conn = None


def seed_auth(password: str) -> str:
    password_hash = auth.hash_password(password)
    db.set_setting(
        "auth",
        {
            "password_hash": password_hash,
            "password_change_required": False,
        },
    )
    return password_hash


def test_login_and_change_password_share_one_critical_section(isolated_auth_db, monkeypatch):
    """登录不能在改密写入后继续使用改密前抓到的 hash 签发 token。"""
    old_password = "old-password-123"
    new_password = "new-password-123"
    old_hash = seed_auth(old_password)
    baseline = asyncio.run(auth.login("admin", old_password, "baseline"))
    assert baseline["ok"]

    verify_entered = threading.Event()
    release_verify = threading.Event()
    real_verify = auth.verify_password

    def controlled_verify(password, stored):
        # login 的同步内核持有 _auth_lock 时停在这里；改密线程应无法越过同一把锁。
        if stored == old_hash and not verify_entered.is_set():
            verify_entered.set()
            assert release_verify.wait(5), "login verify did not get released"
        return real_verify(password, stored)

    monkeypatch.setattr(auth, "verify_password", controlled_verify)
    change_started = threading.Event()

    def run_change():
        change_started.set()
        return auth.change_password(old_password, new_password)

    with ThreadPoolExecutor(max_workers=2) as pool:
        login_future = pool.submit(asyncio.run, auth.login("admin", old_password, "login"))
        try:
            assert verify_entered.wait(5)
            change_future = pool.submit(run_change)
            assert change_started.wait(5)
            acquired = auth._auth_lock.acquire(blocking=False)
            if acquired:
                auth._auth_lock.release()
            assert not acquired, "login must hold the lock across verify and issue"
            assert not change_future.done()
        finally:
            release_verify.set()
        login_result = login_future.result(timeout=5)
        change_result = change_future.result(timeout=5)

    assert login_result["ok"]
    assert change_result["ok"]
    assert not auth.verify_token(login_result["token"])
    assert auth.verify_token(change_result["token"])
    assert not real_verify(old_password, db.get_setting("auth")["password_hash"])
    assert real_verify(new_password, db.get_setting("auth")["password_hash"])
    assert not auth.verify_token(baseline["token"])


def test_concurrent_change_passwords_cannot_both_validate_old_hash(isolated_auth_db, monkeypatch):
    """两个改密请求只能有一个凭同一旧密码成功，后者不能覆盖前者。"""
    old_password = "old-password-123"
    first_password = "first-password-123"
    second_password = "second-password-123"
    old_hash = seed_auth(old_password)

    first_verify_entered = threading.Event()
    release_first_verify = threading.Event()
    second_verify_entered = threading.Event()
    real_verify = auth.verify_password
    verify_calls = 0
    calls_lock = threading.Lock()

    def controlled_verify(password, stored):
        nonlocal verify_calls
        with calls_lock:
            verify_calls += 1
            call_number = verify_calls
        if call_number == 1:
            assert stored == old_hash
            first_verify_entered.set()
            assert release_first_verify.wait(5), "first change verify did not get released"
        elif call_number == 2:
            second_verify_entered.set()
        return real_verify(password, stored)

    monkeypatch.setattr(auth, "verify_password", controlled_verify)

    second_started = threading.Event()

    def run_change(new_password):
        if new_password == second_password:
            second_started.set()
        return auth.change_password(old_password, new_password)

    with ThreadPoolExecutor(max_workers=2) as pool:
        first_future = pool.submit(run_change, first_password)
        try:
            assert first_verify_entered.wait(5)
            second_future = pool.submit(run_change, second_password)
            assert second_started.wait(5)
            acquired = auth._auth_lock.acquire(blocking=False)
            if acquired:
                auth._auth_lock.release()
            assert not acquired, "change must hold the lock from verify through update"
            assert not second_verify_entered.is_set()
        finally:
            release_first_verify.set()
        first_result = first_future.result(timeout=5)
        second_result = second_future.result(timeout=5)

    assert first_result["ok"]
    assert not second_result["ok"]
    assert second_result["error"] == "旧密码错误"
    final_auth = db.get_setting("auth")
    assert real_verify(first_password, final_auth["password_hash"])
    assert not real_verify(second_password, final_auth["password_hash"])
    assert auth.verify_token(first_result["token"])


def test_login_uses_worker_and_failure_sleep_is_outside_auth_lock(isolated_auth_db, monkeypatch):
    """PBKDF2 在线程执行，失败延迟期间不占用认证锁。"""
    seed_auth("correct-password-123")
    caller_thread = threading.get_ident()
    verify_thread = []
    lock_available_during_sleep = threading.Event()
    sleep_delays = []

    def controlled_verify(password, stored):
        verify_thread.append(threading.get_ident())
        return False

    async def controlled_sleep(delay):
        sleep_delays.append(delay)
        # 其他线程也能取锁，避免 RLock 在同线程重入造成假阳性。
        def try_lock():
            acquired = auth._auth_lock.acquire(blocking=False)
            if acquired:
                lock_available_during_sleep.set()
                auth._auth_lock.release()
        with ThreadPoolExecutor(max_workers=1) as pool:
            pool.submit(try_lock).result(timeout=5)

    monkeypatch.setattr(auth, "verify_password", controlled_verify)
    monkeypatch.setattr(auth.asyncio, "sleep", controlled_sleep)
    result = asyncio.run(auth.login("admin", "wrong-password", "sleep-test"))

    assert not result["ok"]
    assert verify_thread and verify_thread[0] != caller_thread
    assert sleep_delays == [auth.FAIL_LOCKOUT_SECONDS]
    assert lock_available_during_sleep.is_set()


def test_failure_pruning_evicts_expired_buckets_without_clearing_live_ones(
    isolated_auth_db, monkeypatch
):
    """失败桶达到全局上限时只淘汰过期桶，不清空有效桶绕过限流。"""
    now = 1_000.0
    monkeypatch.setattr(auth.time, "time", lambda: now)
    with auth._auth_lock:
        auth._failures.update(
            {
                "expired": [now - auth.FAILURE_WINDOW_SECONDS - 1],
                "live": [now - 1],
            }
        )
    auth._record_failure("new")

    with auth._auth_lock:
        assert "expired" not in auth._failures
        assert auth._failures["live"] == [now - 1]
        assert auth._failures["new"] == [now]
        assert len(auth._failures["new"]) <= auth.MAX_FAILURES_PER_KEY


def test_failure_bucket_capacity_preserves_limits_and_reclaims_expired(isolated_auth_db, monkeypatch):
    now = 1_000.0
    monkeypatch.setattr(auth.time, "time", lambda: now)
    monkeypatch.setattr(auth, "MAX_FAILURE_KEYS", 3)
    for key in ("victim", "other-1", "other-2"):
        auth._record_failure(key)
    assert auth.is_rate_limited("victim")
    assert auth.is_rate_limited("new-ip")
    auth._record_failure("new-ip")
    assert len(auth._failures) == 3
    assert "victim" in auth._failures
    assert "new-ip" not in auth._failures
    for _ in range(20):
        auth._record_failure("victim")
    assert len(auth._failures["victim"]) == auth.MAX_FAILURES_PER_KEY
    now += auth.FAILURE_WINDOW_SECONDS
    assert not auth.is_rate_limited("new-ip")
    assert not auth._failures
    auth._record_failure("new-ip")
    assert auth._failures == {"new-ip": [now]}


def test_same_key_concurrent_failures_verify_only_once(isolated_auth_db, monkeypatch):
    seed_auth("old-password-123")
    verify_entered = threading.Event()
    release_verify = threading.Event()
    verify_calls = []
    monkeypatch.setattr(auth.time, "time", lambda: 1_000.0)

    def controlled_verify(password, stored):
        verify_calls.append(password)
        verify_entered.set()
        assert release_verify.wait(5)
        return False

    async def no_sleep(delay):
        pass

    monkeypatch.setattr(auth, "verify_password", controlled_verify)
    monkeypatch.setattr(auth.asyncio, "sleep", no_sleep)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(asyncio.run, auth.login("admin", "wrong", "same-ip"))
        try:
            assert verify_entered.wait(5)
            second = pool.submit(asyncio.run, auth.login("admin", "wrong", "same-ip"))
        finally:
            release_verify.set()
        results = [first.result(timeout=5), second.result(timeout=5)]
    assert verify_calls == ["wrong"]
    assert all(not result["ok"] for result in results)
    assert {result["error"] for result in results} == {
        "用户名或密码错误", "尝试过于频繁，请稍后再试",
    }
    assert auth._failures["same-ip"] == [1_000.0]


@pytest.mark.parametrize("scene", ["stale-login", "double-change"])
def test_race_positive_controls_without_auth_lock(isolated_auth_db, monkeypatch, scene):
    """正控：只移除认证锁，事件调度仍能重现两种原始竞态。"""
    old_password = "old-password-123"
    first_password = "first-password-123"
    second_password = "second-password-123"
    old_hash = seed_auth(old_password)
    captured_old = threading.Event()
    release = threading.Event()
    roles = threading.local()
    real_verify = auth.verify_password
    monkeypatch.setattr(auth, "_auth_lock", nullcontext())

    def controlled_verify(password, stored):
        if getattr(roles, "role", "") == "paused":
            assert stored == old_hash
            captured_old.set()
            assert release.wait(5)
        return real_verify(password, stored)

    monkeypatch.setattr(auth, "verify_password", controlled_verify)

    def paused_operation():
        roles.role = "paused"
        if scene == "stale-login":
            # 同步内核与 async 包装器使用同一认证逻辑。
            return auth._login("admin", old_password, "paused-ip")[0]
        return auth.change_password(old_password, second_password)

    with ThreadPoolExecutor(max_workers=1) as pool:
        paused = pool.submit(paused_operation)
        try:
            assert captured_old.wait(5)
            changed = auth.change_password(old_password, first_password)
            assert changed["ok"]
            assert real_verify(first_password, db.get_setting("auth")["password_hash"])
        finally:
            release.set()
        result = paused.result(timeout=5)
    assert result["ok"]
    assert auth.verify_token(result["token"])
    if scene == "stale-login":
        assert not real_verify(old_password, db.get_setting("auth")["password_hash"])
        assert auth.verify_token(changed["token"])
    else:
        assert real_verify(second_password, db.get_setting("auth")["password_hash"])
        assert not auth.verify_token(changed["token"])


def test_token_expiry_logout_and_password_validation(isolated_auth_db, monkeypatch):
    old_password = "old-password-123"
    old_hash = seed_auth(old_password)
    result = asyncio.run(auth.login("admin", old_password, "baseline"))
    assert result["ok"] and auth.verify_token(result["token"])
    assert not auth.verify_token("")
    assert not auth.change_password("wrong", "new-password-123")["ok"]
    assert not auth.change_password(old_password, "short")["ok"]
    assert not auth.change_password(old_password, old_password)["ok"]
    assert db.get_setting("auth")["password_hash"] == old_hash
    assert auth.verify_token(result["token"])
    auth.logout_token(result["token"])
    assert not auth.verify_token(result["token"])
    result = asyncio.run(auth.login("admin", old_password, "expiry"))
    now = auth.time.time()
    monkeypatch.setattr(auth.time, "time", lambda: now + auth.TOKEN_TTL + 1)
    assert not auth.verify_token(result["token"])
    assert not auth._tokens
