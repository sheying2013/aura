"""无网络探活回归：临时数据库、fake Clash API，不启动 sing-box。"""
import asyncio
from collections import deque
from contextlib import ExitStack
from pathlib import Path
import socket
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock, Mock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import config_manager as cm
import db
import httpx
import ipinfo
import scheduler as s


class Response:
    def __init__(self, status=200, data=None):
        self.status_code = status
        self.data = {"delay": 42} if data is None else data

    def json(self):
        if isinstance(self.data, Exception):
            raise self.data
        return self.data


class ProbeRegressions(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="probe-regression-")
        self.addCleanup(self.tmp.cleanup)
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.old_conn = db._conn
        db._conn = None
        self.stack.enter_context(patch.object(db, "DATA_DIR", self.tmp.name))
        self.stack.enter_context(patch.object(db, "DB_PATH", str(Path(self.tmp.name) / "panel.db")))
        db.init_db()
        self.clock = 10000.0
        self.stack.enter_context(patch.object(s, "time", SimpleNamespace(monotonic=lambda: self.clock, time=time.time)))
        self.stack.enter_context(patch.object(cm, "is_running", return_value=True))
        self.stack.enter_context(patch.object(cm, "_op_lock", asyncio.Lock()))
        self.stack.enter_context(patch.object(cm, "clash_base", return_value="http://fake.invalid"))
        self.stack.enter_context(patch.object(cm, "get_clash_secret", return_value="fake"))
        self.apply = self.stack.enter_context(patch.object(cm, "apply_config", AsyncMock(return_value={"ok": True})))
        self.real_enrich = s._lazy_enrich_ip
        self.enrich = self.stack.enter_context(patch.object(s, "_lazy_enrich_ip", Mock()))
        self.real_sleep = asyncio.sleep

        async def no_wait(*args, **kwargs):
            await self.real_sleep(0)
        self.stack.enter_context(patch.object(asyncio, "sleep", no_wait))
        self.stack.enter_context(patch.object(socket.socket, "connect", side_effect=AssertionError("network forbidden")))
        self.stack.enter_context(patch.object(socket, "getaddrinfo", side_effect=AssertionError("DNS forbidden")))
        self.reply = Response(503, {"message": "synthetic node failure"})
        self.calls = []
        self.puts = []
        self.hook = None
        self.clients = 0
        self.active = 0
        self.peak = 0
        owner = self

        class Client:
            def __init__(self, *args, **kwargs):
                owner.clients += 1
            async def __aenter__(self):
                return self
            async def __aexit__(self, *args):
                return None
            async def get(self, url, **kwargs):
                owner.calls.append((url, kwargs))
                if not url.endswith("/delay"):
                    return Response(data={"now": "direct"})
                owner.active += 1
                owner.peak = max(owner.peak, owner.active)
                try:
                    await owner.real_sleep(0)
                    if owner.hook:
                        return await owner.hook(url, kwargs)
                    if isinstance(owner.reply, Exception):
                        raise owner.reply
                    return owner.reply
                finally:
                    owner.active -= 1
            async def put(self, url, **kwargs):
                owner.puts.append((url, kwargs))
                return Response(204, {})
        self.stack.enter_context(patch.object(httpx, "AsyncClient", Client))
        s._probe_running = False
        s._probe_hist.clear()
        s._probe_failure_since.clear()
        s._probe_tags.clear()
        s._ip_enrich_pending.clear()
        s._ip_enrich_last.clear()
        s._relay_switch_time.clear()

    async def asyncTearDown(self):
        await s.stop_scheduler()
        db._conn.close()
        db._conn = self.old_conn

    def node(self, nid="n", port=52001, **fields):
        return db.create_node({"id": nid, "name": nid, "protocol": "socks", "port": port,
                               "status": "online", "exitIp": "203.0.113.7",
                               "rawConfig": {"server": "203.0.113.7", "server_port": 1080}, **fields})

    def observation(self, fails=19, history=None, elapsed=1300):
        db.update_node("n", {"status": "offline"})
        db.update_node("n", {"consecutiveFails": fails})
        s._probe_hist["n"] = deque(history or [0] * 30, maxlen=30)
        s._probe_failure_since["n"] = self.clock - elapsed

    async def test_manual_all_and_single_never_count_or_disable(self):
        self.node()
        self.observation()
        old_hist = list(s._probe_hist["n"])
        for args in ({"all_": True, "include_disabled": True},
                     {"ids": ["n"], "all_": False}, {}):
            result = await s.probe_nodes(**args)
            self.assertEqual(result[0]["status"], "offline")
            self.assertEqual(db.get_node("n")["consecutiveFails"], 19)
            self.assertEqual(list(s._probe_hist["n"]), old_hist)
        self.apply.assert_not_awaited()

    async def test_short_interval_cannot_disable_before_twenty_minutes(self):
        self.node()
        for i in range(35):
            self.clock = 10000 + i * 10
            await s.probe_nodes(manual=False)
        self.assertEqual(db.get_node("n")["status"], "offline")
        self.apply.assert_not_awaited()
        self.clock = 11200
        await s.probe_nodes(manual=False)
        self.assertEqual(db.get_node("n")["status"], "disabled")
        self.assertTrue(db.get_node("n")["disabledAuto"])
        self.apply.assert_awaited_once()

    async def test_incomplete_window_and_restart_history_are_not_punished(self):
        self.node()
        self.observation(history=[0] * 28)
        await s.probe_nodes(manual=False)
        self.assertEqual(db.get_node("n")["status"], "offline")
        self.assertEqual(s._probe_window_rate("n")[0], 29)
        s._probe_failure_since.clear()
        await s.probe_nodes(manual=False)
        self.assertEqual(db.get_node("n")["status"], "offline")
        self.apply.assert_not_awaited()

    async def test_low_window_rate_alone_does_not_disable(self):
        self.node()
        self.observation(fails=0)
        await s.probe_nodes(manual=False)
        self.assertEqual(db.get_node("n")["consecutiveFails"], 1)
        self.assertEqual(db.get_node("n")["status"], "offline")
        self.apply.assert_not_awaited()

    async def test_failure_observation_never_deletes_nodes(self):
        self.node()
        self.observation(fails=100)
        await s.probe_nodes(manual=False)
        self.assertIsNotNone(db.get_node("n"))
        self.assertEqual(db.get_node("n")["status"], "disabled")

    async def test_management_errors_are_unknown_and_do_not_count(self):
        self.node()
        self.observation()
        for response in (Response(401, {}), Response(404, {}), Response(200, ValueError("bad JSON")),
                         Response(200, []), Response(200, {"delay": "bad"}),
                         httpx.ConnectError("local Clash unavailable")):
            with self.subTest(response=response):
                self.reply = response
                result = await s.probe_nodes(manual=False)
                self.assertEqual(result[0]["status"], "unknown")
                self.assertEqual(db.get_node("n")["consecutiveFails"], 19)
                self.assertEqual(s._probe_window_rate("n"), (30, 0.0))
        self.apply.assert_not_awaited()

    async def test_zero_delay_is_success(self):
        self.node()
        self.reply = Response(data={"delay": 0})
        result = await s.probe_nodes(manual=False)
        self.assertEqual(result[0]["status"], "online")
        self.assertEqual(result[0]["ping"], 0)
        self.assertEqual(len(self.calls), 1)

    async def test_confirmation_keeps_ping_and_uses_one_client(self):
        self.node()
        attempts = 0
        async def confirm(url, kwargs):
            nonlocal attempts
            attempts += 1
            return Response(data={"delay": 123}) if attempts == 4 else self.reply
        self.hook = confirm
        result = await s.probe_nodes(manual=False)
        self.assertEqual(result[0]["ping"], 123)
        self.assertEqual(db.get_node("n")["ping"], 123)
        self.assertEqual(self.clients, 1)
        self.assertEqual(self.calls[-1][1]["params"]["timeout"], "8000")

    async def test_pending_probe_cannot_overwrite_disable_or_changed_tag(self):
        for mode in ("disabled", "port", "protocol"):
            for success in (False, True):
                with self.subTest(mode=mode, success=success):
                    if db.get_node("n"):
                        db.delete_node("n")
                    self.node()
                    s._reset_probe_observation("n")
                    edited = False
                    async def edit(url, kwargs):
                        nonlocal edited
                        if not edited:
                            edited = True
                            fields = {"status": "disabled", "disabledAuto": False} if mode == "disabled" else {mode: 53001 if mode == "port" else "http"}
                            db.update_node("n", fields)
                        return Response() if success else self.reply
                    self.hook = edit
                    result = await s.probe_nodes(manual=False)
                    self.assertEqual(result[0]["status"], "unknown")
                    current = db.get_node("n")
                    self.assertEqual(current["consecutiveFails"], 0)
                    if mode == "disabled":
                        self.assertEqual(current["status"], "disabled")
                    self.assertNotIn("n", s._probe_hist)

    async def test_round_invalidated_by_config_operation_or_stop(self):
        self.node()
        for mode in ("generation", "lock", "stopped"):
            async def change(url, kwargs):
                if mode == "generation":
                    cm._begin_operation()
                elif mode == "lock" and not cm._op_lock.locked():
                    await cm._op_lock.acquire()
                elif mode == "stopped":
                    cm.is_running.return_value = False
                return Response()
            self.hook = change
            self.assertEqual(await s.probe_nodes(manual=False), [])
            self.assertEqual(db.get_node("n")["ping"], 0)
            if cm._op_lock.locked():
                cm._op_lock.release()
            cm.is_running.return_value = True

    async def test_overlap_is_explicit_empty_and_cancellation_releases_gate(self):
        self.node()
        entered, release = asyncio.Event(), asyncio.Event()
        async def wait(url, kwargs):
            entered.set()
            await release.wait()
            return Response()
        self.hook = wait
        task = asyncio.create_task(s.probe_nodes())
        await entered.wait()
        self.assertEqual(await s.probe_nodes(), [])
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertFalse(s._probe_running)

    async def test_manual_disabled_is_not_temporarily_enabled(self):
        self.node(status="disabled", disabledAuto=False)
        result = await s.probe_nodes(include_disabled=True)
        self.assertEqual(result[0]["status"], "disabled")
        self.assertIn("先启用", result[0]["error"])
        self.assertEqual(self.calls, [])
        self.apply.assert_not_awaited()
        self.assertEqual(db.get_node("n")["status"], "disabled")

    async def test_auto_revive_failure_does_not_write_or_reload(self):
        self.node(status="disabled", disabledAuto=True)
        db.update_node("n", {"consecutiveFails": 20})
        for _ in range(3):
            await s.probe_nodes(ids=["n"], all_=False, include_disabled=True)
        current = db.get_node("n")
        self.assertEqual(current["status"], "disabled")
        self.assertEqual(current["consecutiveFails"], 20)
        self.apply.assert_not_awaited()

    async def test_auto_revive_success_clears_window_once_and_reloads_once(self):
        self.node(status="disabled", disabledAuto=True)
        s._probe_hist["n"] = deque([0] * 30, maxlen=30)
        s._probe_failure_since["n"] = self.clock - 2000
        self.reply = Response()
        await s.probe_nodes(ids=["n"], all_=False, include_disabled=True)
        self.assertEqual(db.get_node("n")["status"], "online")
        self.assertFalse(db.get_node("n")["disabledAuto"])
        self.assertEqual(list(s._probe_hist["n"]), [1])
        self.assertNotIn("n", s._probe_failure_since)
        self.apply.assert_awaited_once()

    async def test_user_claiming_auto_disabled_during_probe_blocks_revive(self):
        self.node(status="disabled", disabledAuto=True)
        async def claim(url, kwargs):
            db.update_node("n", {"status": "disabled", "disabledAuto": False})
            return Response()
        self.hook = claim
        result = await s.probe_nodes(include_disabled=True)
        self.assertEqual(result[0]["status"], "unknown")
        self.assertEqual(db.get_node("n")["status"], "disabled")
        self.apply.assert_not_awaited()

    async def test_auto_disabled_config_is_outbound_only(self):
        self.node("active", 52001)
        self.node("auto", 52002, status="disabled", disabledAuto=True)
        self.node("manual", 52003, status="disabled", disabledAuto=False)
        db.set_setting("system", {"inboundPort": 53000})
        db.upsert_relay_domains([{"id": "r", "domain": "example.invalid", "port": 54000}])
        config = cm.build_config()["config"]
        outputs = {o["tag"]: o for o in config["outbounds"]}
        self.assertIn("out-socks-52002", outputs)
        self.assertNotIn("out-socks-52003", outputs)
        self.assertNotIn(52002, [i["listen_port"] for i in config["inbounds"]])
        self.assertNotIn("out-socks-52002", outputs["relay-auto-r"]["outbounds"])
        self.assertNotIn("out-socks-52002", outputs["main-auto"]["outbounds"])
        self.assertFalse(any(r.get("outbound") == "out-socks-52002" for r in config["route"]["rules"]))

    async def test_relay_reuses_delays_and_measures_missing_tags_once_with_bound(self):
        for i in range(5):
            self.node(str(i), 52001 + i)
        db.upsert_relay_domains([{"id": str(i), "port": 54000 + i} for i in range(3)])
        self.reply = Response(data={"delay": 8})
        with patch.object(s, "PROBE_CONCURRENCY", 2):
            await s._sync_relay_exits_after_probe([{"tag": "out-socks-52001", "status": "online", "ping": 1}])
        delays = [url for url, _ in self.calls if url.endswith("/delay")]
        self.assertEqual(len(delays), 4)
        self.assertEqual(len(set(delays)), 4)
        self.assertLessEqual(self.peak, 2)
        self.assertTrue(all(kwargs["json"]["name"] == "out-socks-52001" for _, kwargs in self.puts))

    async def test_reconfirmation_is_bounded_with_primary_requests(self):
        for i in range(6):
            self.node(str(i), 52001 + i)
        with patch.object(s, "PROBE_CONCURRENCY", 2):
            await s.probe_nodes(manual=False)
        self.assertLessEqual(self.peak, 2)
        self.assertEqual(self.clients, 1)
        self.assertEqual(len(self.calls), 24)

    async def test_ippure_mismatched_ip_falls_back_to_ping0_mixed_only(self):
        self.node()
        self.node("other", 52002)
        self.node("ss-entry", 52003, entryProto="ss")
        real_enrich = self.real_enrich
        with patch.object(ipinfo, "lookup", return_value={"exitCountry": "测试"}), \
             patch.object(ipinfo, "lookup_ippure", return_value={"exitIp": "203.0.113.99", "exitRisk": 99}) as pure, \
             patch.object(ipinfo, "lookup_ping0", return_value={"exitRisk": 7}) as ping0:
            real_enrich(db.get_node("n"))
            while "n" in s._ip_enrich_pending:
                await self.real_sleep(0)
            self.assertEqual(db.get_node("n")["exitRisk"], 7)
            self.assertEqual([n["id"] for n in pure.call_args.args[0]], ["n"])
            self.assertTrue(all((n.get("entryProto") or "mixed") == "mixed" for n in ping0.call_args.args[1]))

    async def test_ippure_target_exception_and_ss_entry_fall_back_to_ping0(self):
        self.node()
        self.node("ss-entry", 52002, entryProto="ss")
        with patch.object(ipinfo, "lookup", return_value={}), \
             patch.object(ipinfo, "lookup_ippure", side_effect=ValueError("unavailable")) as pure, \
             patch.object(ipinfo, "lookup_ping0", return_value={"exitRisk": 11}) as ping0:
            self.real_enrich(db.get_node("n"))
            self.real_enrich(db.get_node("ss-entry"))
            while s._ip_enrich_pending:
                await self.real_sleep(0)
            pure.assert_called_once()
            self.assertEqual(db.get_node("n")["exitRisk"], 11)
            self.assertEqual(db.get_node("ss-entry")["exitRisk"], 11)
            self.assertTrue(all(n["id"] == "n" for call in ping0.call_args_list for n in call.args[1]))

    async def test_revive_loop_requests_background_confirmation_budget(self):
        self.node(status="disabled", disabledAuto=True)
        sleeps = 0
        async def tick(delay):
            nonlocal sleeps
            sleeps += 1
            if sleeps > 1:
                raise asyncio.CancelledError()
        with patch.object(asyncio, "sleep", tick), \
             patch.object(s, "probe_nodes", AsyncMock(return_value=[])) as probe:
            with self.assertRaises(asyncio.CancelledError):
                await s._disabled_revive_loop()
            probe.assert_awaited_once_with(ids=["n"], all_=False, include_disabled=True, manual=False)

    async def test_auto_disabled_user_probe_also_gets_confirmation_budget(self):
        self.node(status="disabled", disabledAuto=True)
        await s.probe_nodes(include_disabled=True)
        self.assertEqual(len(self.calls), 4)
        self.assertEqual(self.calls[-1][1]["params"]["timeout"], "8000")
        self.apply.assert_not_awaited()

    async def test_changed_tag_drops_old_failure_elapsed_and_window(self):
        self.node()
        self.observation()
        s._probe_tags["n"] = (52001, "socks")
        db.update_node("n", {"port": 53001})
        await s.probe_nodes(manual=False)
        self.assertEqual(db.get_node("n")["status"], "offline")
        self.assertEqual(list(s._probe_hist["n"]), [0])
        self.assertEqual(s._probe_failure_since["n"], self.clock)
        self.apply.assert_not_awaited()

    async def test_scheduler_tasks_are_idempotent_and_joined(self):
        loop = asyncio.get_running_loop()
        async def idle():
            await asyncio.Event().wait()
        with ExitStack() as stack:
            for name in ("_probe_loop", "_sub_refresh_loop", "_relay_random_loop", "_guard_loop", "_disabled_revive_loop"):
                stack.enter_context(patch.object(s, name, idle))
            s.start_scheduler(loop)
            tasks = list(s._scheduler_tasks)
            self.assertEqual(len(tasks), 5)
            s.start_scheduler(loop)
            self.assertEqual(len(s._scheduler_tasks), 5)
            await s.stop_scheduler()
            self.assertFalse(s._scheduler_tasks)
            self.assertTrue(all(t.done() for t in tasks))


if __name__ == "__main__":
    unittest.main()
