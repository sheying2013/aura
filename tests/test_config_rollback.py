"""配置事务回归：仅执行目标函数，配置 IO、线程、进程与网络全部使用 mock。"""
import ast
import asyncio
import signal
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, Optional
from unittest.mock import AsyncMock, Mock

import pytest


SOURCE_PATH = Path(__file__).resolve().parents[1] / "backend" / "config_manager.py"


@pytest.fixture
def apply_harness():
    # 不导入 config_manager/db 或调用任何内核方法，避免触及项目 data 和外网。
    tree = ast.parse(SOURCE_PATH.read_text())
    impl = next(node for node in tree.body
                if isinstance(node, ast.AsyncFunctionDef) and node.name == "_apply_config_impl")

    def make(*, running=False, prev_good=True, reload_ok=False, starts=(False, True),
             api_status=200):
        old = {"inbounds": [], "marker": "known-good"} if prev_good else None
        candidate = {"inbounds": [], "marker": "candidate"}
        state = {"running": running, "disk": old}
        writes, start_snapshots, reload_snapshots, api_snapshots = [], [], [], []
        outcomes = iter(starts)
        namespace = {"Optional": Optional, "Dict": Dict, "Any": Any,
                     "_last_good_config": old}

        def write(config):
            writes.append(config)
            state["disk"] = config

        async def to_thread(func, *args):
            return func(*args)

        async def start():
            start_snapshots.append((state["disk"], namespace["_last_good_config"]))
            result = next(outcomes)
            if isinstance(result, Exception):
                raise result
            state["running"] = result
            return result

        async def stop():
            state["running"] = False

        async def reload(config):
            reload_snapshots.append((config, namespace["_last_good_config"]))
            return reload_ok

        async def get(*args, **kwargs):
            api_snapshots.append(namespace["_last_good_config"])
            return SimpleNamespace(status_code=api_status)

        client = AsyncMock()
        client.__aenter__.return_value = client
        client.get.side_effect = get
        client_factory = Mock(return_value=client)
        # 未明确覆盖的端口探测一律失败，不可能产生真实 socket。
        open_connection = AsyncMock(side_effect=OSError("mock port unavailable"))
        namespace.update({
            "asyncio": SimpleNamespace(to_thread=AsyncMock(side_effect=to_thread),
                                       sleep=AsyncMock(), wait_for=asyncio.wait_for,
                                       open_connection=open_connection),
            "httpx": SimpleNamespace(AsyncClient=client_factory),
            "_atomic_write_config": Mock(side_effect=write),
            "_detect_port_conflict": Mock(return_value=[]),
            "check_config": Mock(return_value=(True, "OK")),
            "is_running": Mock(side_effect=lambda: state["running"]),
            "_start_unlocked": AsyncMock(side_effect=start),
            "_stop_unlocked": AsyncMock(side_effect=stop),
            "reload_config": AsyncMock(side_effect=reload),
            "get_clash_secret": Mock(return_value="mock-secret"),
            "clash_base": Mock(return_value="http://mock.invalid"),
        })
        exec(compile(ast.Module(body=[impl], type_ignores=[]), str(SOURCE_PATH), "exec"),
             namespace)
        return SimpleNamespace(namespace=namespace, state=state, old=old,
                               candidate=candidate, writes=writes,
                               start_snapshots=start_snapshots,
                               reload_snapshots=reload_snapshots,
                               api_snapshots=api_snapshots, client=client,
                               client_factory=client_factory,
                               open_connection=open_connection,
                               apply=lambda: asyncio.run(namespace["_apply_config_impl"](candidate)))

    return make


@pytest.mark.parametrize("running", [False, True], ids=["start-fails", "reload-and-restart-fail"])
def test_start_failure_rolls_back_config_and_last_good_and_restarts(apply_harness, running):
    harness = apply_harness(running=running)
    result = harness.apply()

    assert result["ok"] is False
    assert result["running"] is True  # 候选失败，但旧配置恢复启动成功。
    assert result["clashApiOk"] is False
    assert "已回滚上一份配置" in result["message"]
    assert harness.writes == [harness.candidate, harness.old]
    assert harness.state["disk"] is harness.old
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.start_snapshots == [(harness.candidate, harness.old),
                                       (harness.old, harness.old)]
    assert harness.namespace["_stop_unlocked"].await_count == (2 if running else 1)
    assert harness.namespace["reload_config"].await_count == int(running)
    harness.client_factory.assert_not_called()


@pytest.mark.parametrize("running", [False, True], ids=["start-succeeds", "reload-succeeds"])
def test_candidate_is_not_last_good_until_runtime_and_api_confirmed(apply_harness, running):
    harness = apply_harness(running=running, reload_ok=True, starts=(True,))
    result = harness.apply()

    assert result["ok"] is True
    assert harness.state["disk"] is harness.candidate
    assert harness.namespace["_last_good_config"] is harness.candidate
    assert harness.writes == [harness.candidate]
    assert harness.api_snapshots == [harness.old]
    assert all(config is harness.candidate and good is harness.old
               for config, good in harness.reload_snapshots)
    assert all(good is harness.old for _, good in harness.start_snapshots)
    harness.namespace["_stop_unlocked"].assert_not_awaited()


@pytest.mark.parametrize("running", [False, True])
def test_api_failure_uses_same_rollback_after_start_or_reload(apply_harness, running):
    harness = apply_harness(running=running, reload_ok=True, starts=(True, True), api_status=503)
    result = harness.apply()

    assert result["ok"] is False
    assert result["running"] is True
    assert "clash API 未就绪" in result["message"]
    assert harness.writes == [harness.candidate, harness.old]
    assert harness.state["disk"] is harness.old
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.api_snapshots == [harness.old] * 10
    assert harness.start_snapshots[-1] == (harness.old, harness.old)
    harness.namespace["_stop_unlocked"].assert_awaited_once()


@pytest.mark.parametrize("starts,api_status", [((False,), 200), ((True,), 503)])
def test_failure_without_known_good_reports_failure_and_does_not_claim_rollback(
        apply_harness, starts, api_status):
    harness = apply_harness(prev_good=False, starts=starts, api_status=api_status)
    result = harness.apply()

    assert result["ok"] is False
    assert result["running"] is False
    assert result["clashApiOk"] is False
    assert "无可用旧配置可回滚" in result["message"]
    assert harness.namespace["_last_good_config"] is None
    assert harness.writes == [harness.candidate]
    harness.namespace["_stop_unlocked"].assert_awaited_once()
    harness.namespace["_start_unlocked"].assert_awaited_once()


@pytest.mark.parametrize("failure", [False, OSError("mock recovery spawn failure")])
def test_rollback_restart_failure_retains_old_file_and_good_pointer(apply_harness, failure):
    harness = apply_harness(starts=(False, failure))
    result = harness.apply()

    assert result["ok"] is False
    assert result["running"] is False
    assert "恢复启动" in result["message"]
    assert harness.state["disk"] is harness.old
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.writes == [harness.candidate, harness.old]


@pytest.mark.parametrize("stage", ["candidate-write", "reload", "start", "api-client"])
def test_runtime_or_candidate_write_exceptions_roll_back(apply_harness, stage):
    harness = apply_harness(running=(stage == "reload"), starts=(True, True))
    if stage == "candidate-write":
        writer = harness.namespace["_atomic_write_config"]
        real_write = writer.side_effect

        def fail_candidate(config):
            if config is harness.candidate:
                raise OSError("mock candidate write failure")
            return real_write(config)

        writer.side_effect = fail_candidate
    elif stage == "reload":
        harness.namespace["reload_config"].side_effect = OSError("mock reload failure")
    elif stage == "start":
        harness = apply_harness(starts=(OSError("mock spawn failure"), True))
    else:
        harness.client_factory.side_effect = OSError("mock client init failure")
    result = harness.apply()

    assert result["ok"] is False
    assert "配置应用异常" in result["message"]
    assert harness.state["disk"] is harness.old
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.start_snapshots[-1] == (harness.old, harness.old)


def test_apply_passes_candidate_to_reload_without_duplicate_probes(apply_harness):
    harness = apply_harness(running=True, reload_ok=True)
    harness.candidate["inbounds"] = [{"listen": "127.0.0.1", "listen_port": 51234}]
    result = harness.apply()

    assert result["ok"] is True
    harness.namespace["reload_config"].assert_awaited_once_with(harness.candidate)
    assert harness.reload_snapshots == [(harness.candidate, harness.old)]
    harness.open_connection.assert_not_awaited()
    harness.namespace["_start_unlocked"].assert_not_awaited()
    harness.namespace["_stop_unlocked"].assert_not_awaited()
    assert harness.api_snapshots == [harness.old]


@pytest.fixture
def reload_harness():
    # 编译真实 reload 函数，但它引用的进程、网络、等待全部是内存 fake。
    tree = ast.parse(SOURCE_PATH.read_text())
    reload_impl = next(node for node in tree.body
                       if isinstance(node, ast.AsyncFunctionDef) and node.name == "reload_config")

    def make(candidate, *, outcomes=None):
        old = {"inbounds": [{"listen": "127.0.0.1", "listen_port": 52001}]}
        writers = []
        connections = []
        outcomes = outcomes or {}
        namespace = {"Dict": Dict, "signal": signal, "_last_good_config": old,
                     "_begin_operation": Mock(), "is_running": Mock(return_value=True),
                     "_proc": SimpleNamespace(send_signal=Mock()),
                     "_signal_singbox": Mock(return_value=1),
                     "get_clash_secret": Mock(return_value="mock-secret"),
                     "clash_base": Mock(return_value="http://mock.invalid")}

        async def connect(host, port):
            connections.append((host, port))
            outcome = outcomes.get((host, port))
            if isinstance(outcome, Exception):
                raise outcome
            writer = SimpleNamespace(close=Mock(), wait_closed=AsyncMock())
            writers.append(writer)
            return object(), writer

        async def wait_for(awaitable, *, timeout):
            # 不做真实等待，但断言生产代码给每一次连接设置了 1s 上限。
            assert timeout == 1.0
            return await awaitable

        client = AsyncMock()
        client.__aenter__.return_value = client
        client.get.return_value = SimpleNamespace(status_code=200)
        namespace.update({
            "asyncio": SimpleNamespace(open_connection=AsyncMock(side_effect=connect),
                                       wait_for=AsyncMock(side_effect=wait_for), sleep=AsyncMock()),
            "httpx": SimpleNamespace(AsyncClient=Mock(return_value=client)),
        })
        exec(compile(ast.Module(body=[reload_impl], type_ignores=[]), str(SOURCE_PATH), "exec"),
             namespace)
        return SimpleNamespace(namespace=namespace, old=old, writers=writers,
                               connections=connections, candidate=candidate,
                               reload=lambda: asyncio.run(namespace["reload_config"](candidate)))

    return make


@pytest.mark.parametrize("candidate", [
    {"inbounds": []},
    {"outbounds": [{"type": "socks", "tag": "disabled-auto-probe"}]},
    {"inbounds": [{"listen": "0.0.0.0", "listen_port": 52002}]},
], ids=["remove-entry", "outbound-only-auto-disabled", "replace-entry"])
def test_real_reload_probes_candidate_instead_of_removed_last_good_entry(reload_harness, candidate):
    harness = reload_harness(candidate)
    assert harness.reload() is True

    expected = [("127.0.0.1", 52002)] if candidate.get("inbounds") else []
    assert harness.connections == expected
    assert harness.namespace["_last_good_config"] is harness.old
    harness.namespace["_begin_operation"].assert_called_once()
    harness.namespace["_proc"].send_signal.assert_called_once_with(signal.SIGHUP)
    assert harness.namespace["asyncio"].wait_for.await_count == len(expected)


def test_real_reload_uses_each_inbound_listen_and_closes_writers(reload_harness):
    candidate = {"inbounds": [
        {"listen": "0.0.0.0", "listen_port": 52002},
        {"listen": "127.0.0.2", "listen_port": 52003},
        {"listen": "::", "listen_port": 52004},
        {"listen": "::1", "listen_port": 52005},
        {"listen_port": 52006},
    ]}
    harness = reload_harness(candidate)
    assert harness.reload() is True

    assert harness.connections == [("127.0.0.1", 52002), ("127.0.0.2", 52003),
                                   ("::1", 52004), ("::1", 52005), ("127.0.0.1", 52006)]
    assert harness.namespace["asyncio"].wait_for.await_count == 5
    for writer in harness.writers:
        writer.close.assert_called_once()
        writer.wait_closed.assert_awaited_once()


@pytest.mark.parametrize("failure", [asyncio.TimeoutError(), OSError("mock new port unavailable")],
                         ids=["connect-times-out", "new-port-unavailable"])
def test_real_reload_timeout_or_new_port_failure_never_confirms_candidate(reload_harness, failure):
    candidate = {"inbounds": [{"listen": "127.0.0.2", "listen_port": 52002}]}
    harness = reload_harness(candidate, outcomes={("127.0.0.2", 52002): failure})
    assert harness.reload() is False

    assert harness.connections == [("127.0.0.2", 52002)] * 13
    assert harness.namespace["asyncio"].wait_for.await_count == 13
    assert harness.namespace["asyncio"].sleep.await_count == 12
    assert harness.namespace["_last_good_config"] is harness.old


def test_actual_reload_removing_entry_does_not_cold_restart_apply(apply_harness, reload_harness):
    harness = apply_harness(running=True, starts=())
    harness.old["inbounds"] = [{"listen": "127.0.0.1", "listen_port": 52001}]
    reload = reload_harness(harness.candidate)
    harness.namespace["reload_config"] = reload.namespace["reload_config"]
    result = harness.apply()

    assert result["ok"] is True
    assert reload.connections == []
    harness.namespace["_start_unlocked"].assert_not_awaited()
    harness.namespace["_stop_unlocked"].assert_not_awaited()
    assert harness.namespace["_last_good_config"] is harness.candidate


def test_actual_reload_new_port_failure_falls_back_and_rolls_back(apply_harness, reload_harness):
    harness = apply_harness(running=True, starts=(False, True))
    harness.candidate["inbounds"] = [{"listen": "127.0.0.2", "listen_port": 52002}]
    reload = reload_harness(harness.candidate, outcomes={
        ("127.0.0.2", 52002): OSError("mock port unavailable"),
    })
    harness.namespace["reload_config"] = reload.namespace["reload_config"]
    result = harness.apply()

    assert result["ok"] is False
    assert result["running"] is True
    assert harness.writes == [harness.candidate, harness.old]
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.start_snapshots == [(harness.candidate, harness.old),
                                       (harness.old, harness.old)]


def test_core_exit_after_api_response_cannot_commit_candidate(apply_harness):
    harness = apply_harness(starts=(True, True))

    async def exited_core(*args, **kwargs):
        harness.state["running"] = False
        return SimpleNamespace(status_code=200)

    harness.client.get.side_effect = exited_core
    result = harness.apply()

    assert result["ok"] is False
    assert "sing-box 已退出" in result["message"]
    assert harness.writes == [harness.candidate, harness.old]
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.start_snapshots[-1] == (harness.old, harness.old)


@pytest.mark.parametrize("stage", ["port-conflict", "invalid-config"])
def test_preflight_failure_does_not_change_config_or_process(apply_harness, stage):
    harness = apply_harness(running=True)
    if stage == "port-conflict":
        harness.namespace["_detect_port_conflict"].return_value = [51234]
    else:
        harness.namespace["check_config"].return_value = (False, "mock invalid config")
    result = harness.apply()

    assert result["ok"] is False
    assert harness.writes == []
    assert harness.namespace["_last_good_config"] is harness.old
    assert harness.state["disk"] is harness.old
    harness.namespace["_start_unlocked"].assert_not_awaited()
    harness.namespace["_stop_unlocked"].assert_not_awaited()
    harness.namespace["reload_config"].assert_not_awaited()
