"""流量统计回归：内存 DB mock 和 HTTP mock，不启动服务或访问网络。"""
import asyncio
import json
import sys
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import stats


@pytest.fixture
def state(monkeypatch):
    nodes = [
        {"id": "n1", "protocol": "socks", "port": 53001,
         "upTraffic": 0, "downTraffic": 0, "status": "online", "ping": 10},
        {"id": "n2", "protocol": "socks", "port": 53002,
         "upTraffic": 0, "downTraffic": 0, "status": "online", "ping": 20},
    ]
    relays = [{"id": "r1", "port": 54001}]
    clock = [100.0]
    for name in ("_conn_state", "_tag_to_node", "_node_rate", "_relay_rate", "_relay_now_cache"):
        monkeypatch.setattr(stats, name, {})
    monkeypatch.setattr(stats, "_relay_tags", set())
    monkeypatch.setattr(stats, "_conn_sample_ts", None)
    monkeypatch.setattr(stats, "_clients", [])
    monkeypatch.setattr(stats, "_global_up_rate", 0.0)
    monkeypatch.setattr(stats, "_global_down_rate", 0.0)
    for name in ("_traffic_task", "_conn_task", "_tag_map_refresh_task", "_broadcast_task"):
        monkeypatch.setattr(stats, name, None)
    monkeypatch.setattr(stats.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(stats.db, "list_nodes", lambda: nodes)
    monkeypatch.setattr(stats.db, "list_relay_domains", lambda: relays)
    monkeypatch.setattr(stats.config_manager, "outbound_tag", lambda proto, port: f"out-{proto}-{port}")
    monkeypatch.setattr(stats.config_manager, "clash_base", lambda: "http://127.0.0.1:9095")
    monkeypatch.setattr(stats.config_manager, "get_clash_secret", lambda: "test-secret")
    monkeypatch.setattr(stats.config_manager, "is_running", lambda: True)
    batches = []

    def batch(deltas):
        batches.append(dict(deltas))
        for node in nodes:
            up, down = deltas.get(node["id"], (0, 0))
            node["upTraffic"] += up
            node["downTraffic"] += down

    monkeypatch.setattr(stats.db, "add_traffic_batch", batch)
    monkeypatch.setattr(stats.db, "add_traffic", Mock(side_effect=AssertionError("per-connection commit")))
    stats._refresh_tag_maps()
    return nodes, relays, clock, batches


def conn(cid="c1", up=100, down=200, chains=None):
    return {"id": cid, "upload": up, "download": down,
            "chains": ["out-socks-53001"] if chains is None else chains}


def test_first_snapshot_counts_bytes_and_batches_all_nodes_once(state):
    nodes, _, _, batches = state
    stats._process_connections([conn(), conn("c2", 300, 400),
                                conn("c3", 50, 75, ["out-socks-53002"])])
    assert batches == [{"n1": (400, 600), "n2": (50, 75)}]
    assert (nodes[0]["upTraffic"], nodes[0]["downTraffic"]) == (400, 600)
    assert stats._node_rate["n1"]["up"] == 80
    assert stats._node_rate["n1"]["down"] == 120
    assert stats.get_stats()["activeConnections"] == 3


def test_same_snapshot_does_not_double_count_or_leave_previous_rate(state):
    _, _, clock, batches = state
    stats._process_connections([conn(), conn("c2", 300, 400)])
    clock[0] += 5
    stats._process_connections([conn(), conn("c2", 300, 400)])
    assert len(batches) == 1
    assert stats._node_rate == {}
    assert stats.get_stats()["nodes"][0]["upRate"] == 0


def test_constant_traffic_rate_does_not_accumulate_previous_windows(state):
    _, _, clock, batches = state
    for sample in range(1, 5):
        stats._process_connections([conn("c1", sample * 100, sample * 200),
                                    conn("c2", sample * 300, sample * 400)])
        assert stats._node_rate["n1"]["up"] == 80
        assert stats._node_rate["n1"]["down"] == 120
        clock[0] += 5
    assert batches == [{"n1": (400, 600)}] * 4


def test_duplicate_ids_and_identical_sampling_time_are_bounded(state):
    _, _, _, batches = state
    stats._process_connections([conn(), conn()])
    stats._process_connections([conn(up=200, down=400), conn(up=200, down=400)])
    assert batches == [{"n1": (100, 200)}, {"n1": (100, 200)}]
    assert stats._node_rate["n1"]["up"] == 20
    assert stats._node_rate["n1"]["down"] == 40


def test_relay_and_real_leaf_are_both_accounted_and_real_leaf_wins(state):
    _, _, _, batches = state
    stats._relay_now_cache["relay-auto-r1"] = "out-socks-53002"
    stats._process_connections([conn(chains=["out-socks-53001", "relay-auto-r1", "relay-auto-r1"])])
    assert batches == [{"n1": (100, 200)}]
    assert stats._relay_rate["relay-auto-r1"]["up"] == 20
    assert stats.get_stats()["relayDomains"][0]["downRate"] == 40


def test_relay_only_chain_uses_now_but_existing_connection_keeps_its_exit(state):
    _, _, clock, batches = state
    stats._relay_now_cache["relay-auto-r1"] = "out-socks-53001"
    stats._process_connections([conn(chains=["relay-auto-r1"])])
    stats._relay_now_cache["relay-auto-r1"] = "out-socks-53002"
    clock[0] += 5
    stats._process_connections([conn(up=200, down=400, chains=["relay-auto-r1"])])
    assert batches == [{"n1": (100, 200)}, {"n1": (100, 200)}]
    assert stats._relay_rate["relay-auto-r1"]["up"] == 20


def test_unknown_leaf_does_not_hide_relay_rate_or_recount_when_resolved(state):
    _, _, clock, batches = state
    stats._process_connections([conn(chains=["relay-auto-r1"])])
    assert batches == []
    assert stats._relay_rate["relay-auto-r1"]["up"] == 20
    stats._relay_now_cache["relay-auto-r1"] = "out-socks-53001"
    clock[0] += 5
    stats._process_connections([conn(up=150, down=250, chains=["relay-auto-r1"])])
    assert batches == [{"n1": (50, 50)}]


def test_deleted_node_cleanup_preserves_baseline_and_cannot_charge_reused_port(state):
    nodes, relays, clock, batches = state
    stats._relay_now_cache["relay-auto-r1"] = "out-socks-53001"
    stats._process_connections([conn(chains=["relay-auto-r1", "out-socks-53001"])])
    nodes.pop(0)
    relays.clear()
    stats._refresh_tag_maps()
    assert stats._node_rate == {}
    assert stats._relay_rate == {}
    assert stats._relay_now_cache == {}
    assert stats._conn_state["c1"]["up"] == 100
    nodes.append({"id": "replacement", "protocol": "socks", "port": 53001,
                  "upTraffic": 0, "downTraffic": 0, "status": "online", "ping": 0})
    stats._refresh_tag_maps()
    clock[0] += 5
    stats._process_connections([conn(up=200, down=400)])
    assert batches == [{"n1": (100, 200)}]
    assert nodes[-1]["upTraffic"] == 0
    assert stats._conn_state["c1"]["up"] == 200


def test_true_empty_snapshot_clears_connections_and_rates(state):
    _, _, clock, batches = state
    stats._process_connections([conn()])
    clock[0] += 5
    stats._process_connections([])
    assert len(batches) == 1
    assert stats._conn_state == {}
    assert stats._node_rate == {}
    assert stats.get_stats()["activeConnections"] == 0


def test_counter_reset_counts_only_current_counter(state):
    _, _, clock, batches = state
    stats._process_connections([conn(up=1000, down=2000)])
    clock[0] += 5
    stats._process_connections([conn(up=100, down=200)])
    assert batches == [{"n1": (1000, 2000)}, {"n1": (100, 200)}]


def test_failed_batch_does_not_advance_connection_baselines(state, monkeypatch):
    _, _, clock, batches = state
    stats._process_connections([conn()])
    original_batch = stats.db.add_traffic_batch
    monkeypatch.setattr(stats.db, "add_traffic_batch", Mock(side_effect=RuntimeError("write failed")))
    clock[0] += 5
    with pytest.raises(RuntimeError, match="write failed"):
        stats._process_connections([conn(up=200, down=400)])
    assert stats._conn_state["c1"]["up"] == 100
    assert stats._conn_sample_ts == 100
    monkeypatch.setattr(stats.db, "add_traffic_batch", original_batch)
    clock[0] += 5
    stats._process_connections([conn(up=300, down=600)])
    assert batches == [{"n1": (100, 200)}, {"n1": (200, 400)}]
    assert stats._node_rate["n1"]["up"] == 20


@pytest.mark.parametrize("failure", ["timeout", "bad_json", "missing_connections", "http_error"])
def test_failed_connection_request_keeps_state_and_counts_only_recovery_delta(state, monkeypatch, failure):
    _, _, clock, batches = state
    stats._process_connections([conn()])
    request = httpx.Request("GET", "http://127.0.0.1:9095/connections")
    responses = {
        "timeout": httpx.ConnectTimeout("mock timeout"),
        "bad_json": httpx.Response(200, text="{", request=request),
        "missing_connections": httpx.Response(200, json={}, request=request),
        "http_error": httpx.Response(503, json={"connections": []}, request=request),
    }
    results = [responses[failure], httpx.Response(200, json={"connections": [conn(up=300, down=600)]}, request=request)]
    sleeps = []
    client_args = []

    class Client:
        def __init__(self, **kwargs):
            client_args.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def get(self, *args, **kwargs):
            result = results.pop(0)
            if isinstance(result, Exception):
                raise result
            return result

    async def sleep(seconds):
        sleeps.append(seconds)
        clock[0] += seconds
        if len(sleeps) == 1:
            assert stats._conn_state["c1"]["up"] == 100
        else:
            raise asyncio.CancelledError

    monkeypatch.setattr(stats.httpx, "AsyncClient", Client)
    monkeypatch.setattr(stats, "_update_relay_now", AsyncMock())
    monkeypatch.setattr(stats.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(stats._connections_sampler())
    assert batches == [{"n1": (100, 200)}, {"n1": (200, 400)}]
    assert all(args["trust_env"] is False for args in client_args)


def test_traffic_frames_are_rates_not_deltas_and_totals_are_persisted(state, monkeypatch):
    nodes, _, _, _ = state
    nodes[0].update(upTraffic=12345, downTraffic=54321)
    observed = []
    client_args = []

    class Stream:
        status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        async def aiter_lines(self):
            for up, down in [(1000, 2000), (1000, 2000), (900, 0), (0, 0)]:
                yield json.dumps({"up": up, "down": down})
                observed.append(stats.get_stats()["global"])
            raise asyncio.CancelledError

    class Client:
        def __init__(self, **kwargs):
            client_args.append(kwargs)

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            pass

        def stream(self, *args, **kwargs):
            return Stream()

    monkeypatch.setattr(stats.httpx, "AsyncClient", Client)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(stats._traffic_reader())
    assert [(g["upRate"], g["downRate"]) for g in observed] == [(1000, 2000), (1000, 2000), (900, 0), (0, 0)]
    assert all(g["upTotal"] == 12345 and g["downTotal"] == 54321 for g in observed)
    assert client_args == [{"timeout": None, "trust_env": False}]


def test_stopped_core_reports_zero_global_rate(state, monkeypatch):
    monkeypatch.setattr(stats.config_manager, "is_running", lambda: False)
    monkeypatch.setattr(stats, "_global_up_rate", 1000)
    monkeypatch.setattr(stats, "_global_down_rate", 2000)

    async def sleep(seconds):
        raise asyncio.CancelledError

    monkeypatch.setattr(stats.asyncio, "sleep", sleep)
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(stats._traffic_reader())
    assert stats.get_stats()["global"]["upRate"] == 0
    assert stats.get_stats()["global"]["downRate"] == 0


def test_sse_includes_active_connections_even_before_any_traffic(state, monkeypatch):
    sleeps = []

    async def sleep(seconds):
        sleeps.append(seconds)
        if len(sleeps) == 2:
            raise asyncio.CancelledError

    monkeypatch.setattr(stats.asyncio, "sleep", sleep)
    queue = stats.subscribe_sse()
    with pytest.raises(asyncio.CancelledError):
        asyncio.run(stats._broadcast())
    payload = json.loads(queue.get_nowait())
    assert payload["activeConnections"] == 0
    assert payload["upRate"] == payload["downRate"] == 0
    stats.unsubscribe_sse(queue)
    assert stats._clients == []


def test_relay_cache_client_never_uses_environment_proxy(state, monkeypatch):
    factory = Mock(return_value=AsyncMock())
    factory.return_value.__aenter__.return_value.get.return_value = httpx.Response(200, json={"now": "out-socks-53001"})
    monkeypatch.setattr(stats.httpx, "AsyncClient", factory)
    asyncio.run(stats._update_relay_now())
    factory.assert_called_once_with(timeout=2.0, trust_env=False)
    assert stats._relay_now_cache["relay-auto-r1"] == "out-socks-53001"


def test_status_check_runs_off_the_event_loop(state, monkeypatch):
    worker = AsyncMock(return_value=True)
    monkeypatch.setattr(stats.asyncio, "to_thread", worker)
    assert asyncio.run(stats._is_running()) is True
    worker.assert_awaited_once_with(stats.config_manager.is_running)


def test_task_stop_before_start_and_duplicate_start_are_safe(state, monkeypatch):
    async def worker():
        try:
            await asyncio.Event().wait()
        finally:
            finalized.append(True)

    finalized = []
    for name in ("_traffic_reader", "_connections_sampler", "_tag_map_refresh_loop", "_broadcast"):
        monkeypatch.setattr(stats, name, worker)

    async def exercise():
        await stats.stop_tasks()
        stats.start_tasks(asyncio.get_running_loop())
        tasks = (stats._traffic_task, stats._conn_task, stats._tag_map_refresh_task, stats._broadcast_task)
        stats.start_tasks(asyncio.get_running_loop())
        assert tasks == (stats._traffic_task, stats._conn_task, stats._tag_map_refresh_task, stats._broadcast_task)
        await asyncio.sleep(0)
        await stats.stop_tasks()
        assert all(task.done() for task in tasks)
        assert len(finalized) == 4
        assert all(getattr(stats, name) is None for name in
                   ("_traffic_task", "_conn_task", "_tag_map_refresh_task", "_broadcast_task"))
        await stats.stop_tasks()

    asyncio.run(exercise())
