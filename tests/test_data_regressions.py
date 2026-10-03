"""真实 SQLite 业务回归；禁止外部网络和内核进程，仅 mock 订阅拉取/配置应用。"""
import asyncio
import copy
import json
import socket
import subprocess
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
import db
import models
import subs_proxy


@pytest.fixture(autouse=True)
def isolated_db(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setattr(db, "_conn", None)

    def forbidden(*args, **kwargs):
        raise AssertionError("离线回归禁止网络或内核进程")

    # socketpair 供 asyncio 事件循环使用；只禁止真正出站操作。
    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(socket.socket, "connect_ex", forbidden)
    monkeypatch.setattr(socket.socket, "sendto", forbidden)
    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(subprocess, "Popen", forbidden)
    monkeypatch.setattr(asyncio, "create_subprocess_exec", forbidden)
    db.init_db()
    yield
    if db._conn is not None:
        db._conn.close()


def node(nid="existing", **overrides):
    base = {
        "id": nid, "name": "existing", "protocol": "ss", "group": "local-group",
        "port": 52001, "segment": 52, "authUser": "local-user", "authPass": "local-pass",
        "status": "online", "ping": 42, "exitIp": "203.0.113.8",
        "upTraffic": 10, "downTraffic": 20, "entryProto": "ss", "ssPass": "entry-ss-pass",
        "selected": True, "subName": "test-sub", "rawConfig": {
            "type": "shadowsocks", "server": "node.invalid", "server_port": 443,
            "method": "aes-256-gcm", "password": "old-password"},
    }
    return {**base, **overrides}


def create_sub():
    return db.create_sub("https://subscription.invalid/demo", "test-sub", "upstream-group")


def parsed_node(raw=None, name="existing", protocol="ss"):
    return {"name": name, "protocol": protocol,
            "rawConfig": raw if raw is not None else node()["rawConfig"]}


@pytest.mark.parametrize("auto", [False, True])
def test_batch_insert_matches_23_parameter_schema(auto):
    created = node("batch", disabledAuto=auto)
    result = db.create_node_batch([created])
    assert result["created"] == 1 and result["updated"] == 0
    assert result["skipped"] == 0
    assert db.get_node("batch")["disabledAuto"] is auto
    assert db.get_node("batch")["port"] == 52001
    assert db.get_node("batch")["createdAt"] is not None


def test_batch_auto_allocates_distinct_ports_and_skips_reserved():
    db.set_setting("system", {"reservedPorts": ["bad", "52001", 52003]})
    rows = [node(f"batch-{i}", port=0, rawConfig={**node()["rawConfig"], "server": f"node-{i}.invalid"})
            for i in range(3)]
    result = db.create_node_batch(rows)
    assert result["created"] == 3
    assert [n["port"] for n in result["items"]] == [52002, 52004, 52005]


@pytest.mark.parametrize("bad", [-1, 65536, "broken", 4.5, True])
def test_batch_rejects_invalid_listener_ports(bad):
    result = db.create_node_batch([node("bad", port=bad)])
    assert result["created"] == 0 and result["skipped"] == 1
    assert db.list_nodes() == []


@pytest.mark.parametrize("bad", ["broken", -1, 65536, 4.5, True])
def test_batch_bad_upstream_port_does_not_crash_or_block_valid_rows(bad):
    bad_row = node("bad", rawConfig={**node()["rawConfig"], "server_port": bad})
    good_row = node("good", rawConfig={**node()["rawConfig"], "server": "other.invalid"})
    result = db.create_node_batch([bad_row, good_row])
    assert result["created"] == 1 and result["skipped"] == 1
    assert db.get_node("bad") is None
    assert db.get_node("good") is not None


def test_batch_automatic_port_exhaustion_does_not_cross_65535():
    db.set_setting("system", {"reservedPorts": list(range(52001, 65536))})
    result = db.create_node_batch([node("exhausted", port=0)])
    assert result["created"] == 0 and result["skipped"] == 1
    assert db.list_nodes() == []
    assert db.get_next_available_port(None) is None


def test_batch_explicit_port_conflict_at_65535_is_skipped():
    db.create_node(node("last", port=65535))
    result = db.create_node_batch([node("overflow", port=65535,
        rawConfig={**node()["rawConfig"], "server": "other.invalid"})])
    assert result["created"] == 0 and result["skipped"] == 1
    assert db.get_node("overflow") is None


@pytest.mark.parametrize("bad", [-1, 65536, "broken", 4.5, True])
def test_invalid_port_updates_leave_node_unchanged(bad):
    before = db.create_node(node())
    assert db.update_node_port("existing", bad) is None
    assert db.update_node("existing", {"port": bad}) is None
    assert db.get_next_available_port(bad) is None
    assert db.get_node("existing") == before


def test_port_pool_exhaustion_update_is_noop():
    before = db.create_node(node())
    db.set_setting("system", {"reservedPorts": list(range(52001, 65536))})
    assert db.update_node_port("existing", None) is None
    assert db.update_node("existing", {"port": 0}) is None
    assert db.get_node("existing") == before


@pytest.mark.parametrize("status", ["disabled", "offline", "online"])
def test_explicit_manual_status_resets_failures_and_auto_source(status):
    db.create_node(node(status="disabled", disabledAuto=True))
    db.connect().execute("UPDATE nodes SET consecutive_fails=24 WHERE id='existing'")
    db.connect().commit()
    changed = db.update_node("existing", {"status": status})
    assert changed["status"] == status
    assert changed["consecutiveFails"] == 0
    assert changed["disabledAuto"] is False


def test_non_status_patch_preserves_management_state():
    db.create_node(node(status="disabled", disabledAuto=True))
    db.connect().execute("UPDATE nodes SET consecutive_fails=24 WHERE id='existing'")
    db.connect().commit()
    changed = db.update_node("existing", {"exitIp": "203.0.113.9", "name": "renamed"})
    assert changed["status"] == "disabled"
    assert changed["consecutiveFails"] == 24
    assert changed["disabledAuto"] is True


def test_historical_disabled_migration_does_not_assign_auto_source():
    db.create_node(node("old-manual", status="disabled"))
    c = db.connect()
    c.execute("ALTER TABLE nodes DROP COLUMN disabled_auto")
    c.commit()
    db.init_db()
    old = db.get_node("old-manual")
    assert old["status"] == "disabled"
    assert old["disabledAuto"] is False
    c.execute("UPDATE nodes SET disabled_auto=1 WHERE id='old-manual'")
    c.commit()
    db.init_db()
    assert db.get_node("old-manual")["disabledAuto"] is True


def test_probe_failure_counter_and_manual_non_counting():
    db.create_node(node())
    tag = {"expected_port": 52001, "expected_protocol": "ss"}
    assert db.update_node_probe("existing", 0, "offline", **tag) == 1
    assert db.update_node_probe("existing", 0, "offline", count_failure=False, **tag) == 1
    assert db.update_node_probe("existing", 23, "online", **tag) == 0
    after = db.get_node("existing")
    assert after["ping"] == 23 and after["status"] == "online"


@pytest.mark.parametrize("status", ["online", "offline"])
def test_probe_rejects_late_result_after_manual_disable(status):
    db.create_node(node())
    db.update_node("existing", {"status": "disabled"})
    before = db.get_node("existing")
    assert db.update_node_probe("existing", 17, status,
        expected_port=52001, expected_protocol="ss") is None
    assert db.get_node("existing") == before


@pytest.mark.parametrize("tag", [
    {"expected_port": 52002, "expected_protocol": "ss"},
    {"expected_port": 52001, "expected_protocol": "vless"},
])
def test_probe_rejects_changed_tag(tag):
    before = db.create_node(node())
    assert db.update_node_probe("existing", 7, "online", **tag) is None
    assert db.get_node("existing") == before


def test_probe_missing_node_returns_none_for_both_outcomes():
    assert db.update_node_probe("missing", 0, "offline") is None
    assert db.update_node_probe("missing", 3, "online") is None


def test_disable_probe_cas_threshold_state_counter_and_tag():
    db.create_node(node())
    c = db.connect()
    c.execute("UPDATE nodes SET consecutive_fails=20 WHERE id='existing'")
    c.commit()
    good = {"expected_port": 52001, "expected_protocol": "ss", "expected_fails": 20}
    for mismatch in [{"expected_fails": 19}, {"expected_fails": 21},
                     {"expected_port": 52002}, {"expected_protocol": "vless"}]:
        assert db.disable_node_after_probe("existing", **{**good, **mismatch}) is False
    assert db.disable_node_after_probe("existing", **good) is True
    after = db.get_node("existing")
    assert after["status"] == "disabled" and after["disabledAuto"] is True
    assert after["consecutiveFails"] == 20
    assert db.disable_node_after_probe("existing", **good) is False


def test_disable_probe_cas_preserves_manual_disabled_source():
    db.create_node(node())
    db.update_node("existing", {"status": "disabled"})
    assert db.disable_node_after_probe("existing", expected_port=52001,
        expected_protocol="ss", expected_fails=20) is False
    assert db.get_node("existing")["disabledAuto"] is False


def test_revive_only_matching_auto_disabled_tag():
    db.create_node(node(status="disabled", disabledAuto=True))
    c = db.connect()
    c.execute("UPDATE nodes SET consecutive_fails=21 WHERE id='existing'")
    c.commit()
    before = db.get_node("existing")
    assert db.revive_node_probe("existing", 24, expected_port=52002, expected_protocol="ss") is None
    assert db.revive_node_probe("existing", 24, expected_port=52001, expected_protocol="vless") is None
    assert db.get_node("existing") == before
    assert db.revive_node_probe("existing", 24, expected_port=52001, expected_protocol="ss") == 0
    revived = db.get_node("existing")
    assert revived["status"] == "online" and revived["ping"] == 24
    assert revived["consecutiveFails"] == 0 and revived["disabledAuto"] is False
    assert db.revive_node_probe("existing", 25, expected_port=52001, expected_protocol="ss") is None


def test_revive_does_not_override_user_manual_disable():
    db.create_node(node(status="disabled", disabledAuto=True))
    db.update_node("existing", {"status": "disabled"})
    before = db.get_node("existing")
    assert db.revive_node_probe("existing", 25, expected_port=52001, expected_protocol="ss") is None
    assert db.get_node("existing") == before


@pytest.mark.parametrize("status", ["online", "disabled"])
def test_subscription_updates_only_upstream_fields_and_counts_real_changes(status):
    sub = create_sub()
    db.create_node(node(subId=sub["id"], status=status, disabledAuto=(status == "disabled")))
    db.update_node("existing", {"consecutiveFails": 21, "exitCountry": "JP", "exitFlag": "JP",
        "exitCity": "Tokyo", "exitType": "isp", "exitScore": 99, "exitRisk": 1})
    before = db.get_node("existing")
    new_raw = {**before["rawConfig"], "password": "new-password"}
    result = subs_proxy.import_nodes(sub["id"], "remote-group", "new-sub-name",
        [parsed_node(new_raw, "renamed")], update_existing=True)
    assert (result["created"], result["updated"], result["duplicate"]) == (0, 1, 0)
    after = db.get_node("existing")
    for key in before.keys() - {"name", "protocol", "rawConfig", "subName", "stale", "updatedAt"}:
        assert after[key] == before[key], key
    assert after["rawConfig"]["password"] == "new-password"
    assert after["name"] == "renamed" and after["subName"] == "new-sub-name"
    assert result["items"][0] == after
    repeated = subs_proxy.import_nodes(sub["id"], "ignored-group", "new-sub-name",
        [parsed_node(dict(reversed(list(new_raw.items()))), "renamed")], update_existing=True)
    assert repeated["updated"] == 0 and repeated["duplicate"] == 1
    assert db.get_node("existing") == after


def test_subscription_duplicate_skip_is_not_an_update():
    sub = create_sub()
    before = db.create_node(node(subId=sub["id"]))
    result = subs_proxy.import_nodes(sub["id"], "group", "sub", [parsed_node()], update_existing=False)
    assert (result["created"], result["updated"], result["skipped"], result["duplicate"]) == (0, 0, 1, 1)
    assert db.get_node("existing") == before


@pytest.mark.parametrize("protocol,field,old,new", [
    ("ss", "password", "old-password", "new-password"),
    ("vless", "uuid", "11111111-1111-1111-1111-111111111111", "22222222-2222-2222-2222-222222222222"),
])
def test_existing_only_refresh_applies_rotated_credential_and_skips_noop(monkeypatch, protocol, field, old, new):
    import config_manager
    sub = create_sub()
    raw = {"type": "shadowsocks" if protocol == "ss" else protocol, "server": "node.invalid",
           "server_port": 443, field: old}
    if protocol == "ss":
        raw["method"] = "aes-256-gcm"
    db.create_node(node(subId=sub["id"], rawConfig=raw, protocol=protocol))
    apply = AsyncMock(return_value={"ok": True})
    fetch = AsyncMock(return_value={"ok": True, "content": json.dumps([{**raw, "name": "existing", field: new}])})
    monkeypatch.setattr(subs_proxy, "fetch_subscription", fetch)
    monkeypatch.setattr(config_manager, "apply_config", apply)
    response = asyncio.run(subs_proxy.refresh_sub(db.get_sub(sub["id"])))
    assert response["ok"] and response["imported"] == 0 and response["updated"] == 1
    assert apply.await_count == 1
    assert db.get_node("existing")["rawConfig"][field] == new
    built = config_manager.build_config()["config"]
    tag = config_manager.outbound_tag(protocol, 52001)
    assert next(out for out in built["outbounds"] if out["tag"] == tag)[field] == new
    response = asyncio.run(subs_proxy.refresh_sub(db.get_sub(sub["id"])))
    assert response["updated"] == 0 and response["imported"] == 0
    assert apply.await_count == 1


def test_refresh_apply_failure_persists_pending_and_retries_same_content(monkeypatch):
    import config_manager
    sub = create_sub()
    raw = {**node()["rawConfig"], "password": "rotated-password"}
    db.create_node(node(subId=sub["id"], rawConfig={**raw, "password": "old-password"}))
    content = json.dumps([{**raw, "name": "existing"}])
    monkeypatch.setattr(subs_proxy, "fetch_subscription", AsyncMock(return_value={"ok": True, "content": content}))
    apply = AsyncMock(side_effect=[{"ok": False, "message": "check failed"}, {"ok": True}])
    monkeypatch.setattr(config_manager, "apply_config", apply)
    first = asyncio.run(subs_proxy.refresh_sub(db.get_sub(sub["id"])))
    assert first["ok"] is False and first["degraded"] is True
    assert first["error"] == "配置应用失败: check failed"
    assert db.get_sub(sub["id"])["pendingApply"] is True
    assert db.get_sub(sub["id"])["lastError"] == "配置应用失败: check failed"
    second = asyncio.run(subs_proxy.refresh_sub(db.get_sub(sub["id"])))
    assert second["ok"] is True and second["updated"] == 0 and second["imported"] == 0
    assert apply.await_count == 2
    assert db.get_sub(sub["id"])["pendingApply"] is False
    assert db.get_sub(sub["id"])["lastError"] is None


def test_refresh_apply_exception_persists_pending(monkeypatch):
    import config_manager
    sub = create_sub()
    raw = {**node()["rawConfig"], "password": "exception-password"}
    monkeypatch.setattr(subs_proxy, "fetch_subscription", AsyncMock(return_value={"ok": True, "content": json.dumps([raw])}))
    apply = AsyncMock(side_effect=RuntimeError("no kernel"))
    monkeypatch.setattr(config_manager, "apply_config", apply)
    result = asyncio.run(subs_proxy.refresh_sub(sub))
    assert result["ok"] is False and result["degraded"] is True
    assert "no kernel" in result["error"]
    assert db.get_sub(sub["id"])["pendingApply"] is True


def test_refresh_new_nodes_applies_once(monkeypatch):
    import config_manager
    sub = create_sub()
    monkeypatch.setattr(subs_proxy, "fetch_subscription", AsyncMock(return_value={
        "ok": True, "content": json.dumps([{**node()["rawConfig"], "name": "existing"}])}))
    apply = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(config_manager, "apply_config", apply)
    result = asyncio.run(subs_proxy.refresh_sub(sub))
    assert result["imported"] == 1 and result["updated"] == 0
    assert apply.await_count == 1 and len(db.list_nodes()) == 1


def test_batch_refresh_failure_reads_snapshot_and_preserves_local_fields(monkeypatch):
    import config_manager
    sub = create_sub()
    snapshot = json.dumps([parsed_node()])
    db.update_sub(sub["id"], {"snapshot": snapshot})
    db.create_node(node(subId=sub["id"], status="disabled"))
    before = copy.deepcopy(db.get_node("existing"))
    assert "snapshot" not in db.list_subs()[0]
    fetch = AsyncMock(return_value={"ok": False, "error": "offline-fetch"})
    apply = AsyncMock()
    monkeypatch.setattr(subs_proxy, "fetch_subscription", fetch)
    monkeypatch.setattr(config_manager, "apply_config", apply)
    result = asyncio.run(subs_proxy.refresh_subs())[0]
    assert result["ok"] is False and result["stale"] is True and result["degraded"] is True
    assert result["count"] == 1 and result["imported"] == 0
    assert apply.await_count == 0
    after = db.get_node("existing")
    assert after["stale"] is True
    assert {k:v for k,v in after.items() if k not in {"stale", "updatedAt"}} == {
        k:v for k,v in before.items() if k not in {"stale", "updatedAt"}}
    listed = db.list_subs()[0]
    detail = db.get_sub(sub["id"])
    assert listed["degraded"] and detail["degraded"]
    assert not listed["stale"] and not detail["stale"]
    assert models.Subscription(**listed).model_dump()["degraded"] is True
    assert models.SubRefreshResult(**result).model_dump()["degraded"] is True


def test_deleted_snapshot_node_is_not_reimported_after_failure(monkeypatch):
    sub = create_sub()
    db.update_sub(sub["id"], {"snapshot": json.dumps([parsed_node()])})
    db.create_node(node(subId=sub["id"]))
    db.delete_node("existing")
    monkeypatch.setattr(subs_proxy, "fetch_subscription", AsyncMock(return_value={"ok": False, "error": "no-fetch"}))
    result = asyncio.run(subs_proxy.refresh_subs())[0]
    assert result["degraded"] is True and result["imported"] == 0
    assert db.list_nodes() == []


def test_failure_without_snapshot_exposes_stale_subscription(monkeypatch):
    sub = create_sub()
    monkeypatch.setattr(subs_proxy, "fetch_subscription", AsyncMock(return_value={"ok": False, "error": "no-fetch"}))
    asyncio.run(subs_proxy.refresh_subs())
    detail = models.Subscription(**db.get_sub(sub["id"])).model_dump()
    assert detail["stale"] is True and detail["degraded"] is False


def test_add_traffic_batch_single_commit_and_negative_clamp():
    db.create_node(node("a"))
    db.create_node(node("b", port=52002))
    c = db.connect()
    statements = []
    c.set_trace_callback(statements.append)
    db.add_traffic_batch({"a": (4, 7), "b": (-9, 3), "missing": (10, 20)})
    c.set_trace_callback(None)
    assert sum(stmt == "COMMIT" for stmt in statements) == 1
    assert db.get_node("a")["upTraffic"] == 14
    assert db.get_node("a")["downTraffic"] == 27
    assert db.get_node("b")["upTraffic"] == 10
    assert db.get_node("b")["downTraffic"] == 23


def test_response_models_keep_added_fields():
    assert models.NodeBatchResponse(updated=2).model_dump()["updated"] == 2
    assert models.SubRefreshResult(id="sub", ok=True, updated=2).model_dump()["updated"] == 2
    assert models.StatsResponse(activeConnections=3).model_dump(by_alias=True)["activeConnections"] == 3
