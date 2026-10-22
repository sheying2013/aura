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


if __name__ == "__main__":
    unittest.main()
