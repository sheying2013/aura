"""崩溃守护回归：限流冷却结束后必须能重新拉起 sing-box。

历史缺陷（2026-10-22 oracle日本-2）：_restart_times 在判断之前无条件 append，
冷却期内每一轮探测又续期一条时间戳（GUARD_INTERVAL=10s，60s 窗口恒有 6 条），
len > 3 永远成立 → 永久冷却 → sing-box FATAL 退出后再也没被拉起，
面板整站瘫痪 43 分钟才被人工发现。
"""
import asyncio
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import config_manager  # noqa: E402
import scheduler  # noqa: E402


class GuardLoopTest(unittest.IsolatedAsyncioTestCase):
    async def test_cooldown_expires_and_restarts_again(self):
        restarts = []

        async def fake_start():
            restarts.append(1)
            return True

        class FakeProc:
            pass

        loop = asyncio.get_running_loop()
        with patch.object(scheduler, "GUARD_INTERVAL", 0.01), \
                patch.object(scheduler, "GUARD_WINDOW", 0.05), \
                patch.object(scheduler, "MAX_RESTARTS_PER_MIN", 3), \
                patch.object(scheduler, "_restart_times", []), \
                patch.object(scheduler, "_guard_paused", False), \
                patch.object(config_manager, "get_proc", lambda: FakeProc()), \
                patch.object(config_manager, "is_running", lambda: False), \
                patch.object(config_manager, "start", fake_start):
            task = loop.create_task(scheduler._guard_loop())
            await asyncio.sleep(0.6)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        # 旧实现（无条件 append）：窗口内恒满，只有最初 3 次重启；
        # 新实现：冷却过期后继续重启，0.6s / 0.05s 窗口远多于 6 次。
        self.assertGreater(
            len(restarts), 6,
            f"冷却结束后未能恢复重启，实际只有 {len(restarts)} 次",
        )

    async def test_no_restart_when_process_never_started(self):
        """手动停止/从未启动（_proc 为 None）时守护不得自行拉起。"""
        restarts = []

        async def fake_start():
            restarts.append(1)
            return True

        loop = asyncio.get_running_loop()
        with patch.object(scheduler, "GUARD_INTERVAL", 0.01), \
                patch.object(scheduler, "_restart_times", []), \
                patch.object(scheduler, "_guard_paused", False), \
                patch.object(config_manager, "get_proc", lambda: None), \
                patch.object(config_manager, "is_running", lambda: False), \
                patch.object(config_manager, "start", fake_start):
            task = loop.create_task(scheduler._guard_loop())
            await asyncio.sleep(0.2)
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

        self.assertEqual(restarts, [], "进程未启动时守护不应干预")


class FdWatchdogTest(unittest.IsolatedAsyncioTestCase):
    """fd 泄漏看门狗：进程活着但 fd 上千时必须重启回收。

    历史缺陷（2026-10-22 新加坡 arm-3）：出站拨回本机公网 IP 的 hairpin 连接半开不释放，
    sing-box fd 1875、load 224、sshd 无法 fork，而崩溃守护只认「进程退出」，
    面板一直 200 却整机失联，靠人工发现。现在守护每轮顺带体检测 fd。
    """

    def setUp(self):
        self._orig_at = scheduler._fd_restart_at
        scheduler._fd_restart_at = 0.0

    def tearDown(self):
        scheduler._fd_restart_at = self._orig_at

    async def test_recycles_singbox_on_fd_leak(self):
        calls = []

        async def fake_stop():
            calls.append("stop")

        async def fake_start():
            calls.append("start")
            return True

        with patch.object(scheduler, "FD_LIMIT", 100),                 patch.object(config_manager, "singbox_fd_count", lambda: 1875),                 patch.object(config_manager, "stop", fake_stop),                 patch.object(config_manager, "start", fake_start):
            recycled = await scheduler._recycle_if_fd_leak()

        self.assertTrue(recycled)
        self.assertEqual(calls, ["stop", "start"])

    async def test_no_recycle_under_limit(self):
        async def boom(*_a, **_k):
            raise AssertionError("未超限不应重启")

        with patch.object(scheduler, "FD_LIMIT", 1200),                 patch.object(config_manager, "singbox_fd_count", lambda: 20),                 patch.object(config_manager, "stop", boom),                 patch.object(config_manager, "start", boom):
            self.assertFalse(await scheduler._recycle_if_fd_leak())

    async def test_cooldown_prevents_restart_loop(self):
        calls = []

        async def fake_stop():
            calls.append("stop")

        async def fake_start():
            calls.append("start")
            return True

        with patch.object(scheduler, "FD_LIMIT", 100),                 patch.object(scheduler, "FD_RESTART_COOLDOWN", 300),                 patch.object(config_manager, "singbox_fd_count", lambda: 5000),                 patch.object(config_manager, "stop", fake_stop),                 patch.object(config_manager, "start", fake_start):
            self.assertTrue(await scheduler._recycle_if_fd_leak())
            # 泄漏没修好时下一轮仍会看到 5000 个 fd，冷却期内必须忍住不重启
            self.assertFalse(await scheduler._recycle_if_fd_leak())

        self.assertEqual(calls, ["stop", "start"])

    async def test_counter_failure_does_not_break_guard(self):
        def boom():
            raise OSError("/proc 不可读")

        with patch.object(config_manager, "singbox_fd_count", boom):
            self.assertFalse(await scheduler._recycle_if_fd_leak())


if __name__ == "__main__":
    unittest.main()
