"""Backend regressions for singbox-relay:
1. convert-entry, batch-group, groups/rename apply failure & contract consistency
2. settings offlineGraceFails range validation (1..10) and roundtrip
3. scheduler offlineGraceFails background grace vs threshold vs manual immediate failure
"""
import asyncio
import sqlite3
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import AsyncMock, Mock, patch

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import app
import auth
import config_manager as cm
import db
import panel_config
import scheduler as s


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    monkeypatch.delenv("AUTH_DISABLED", raising=False)
    monkeypatch.setattr(db, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setattr(db, "_conn", None)
    monkeypatch.setattr(panel_config, "CONF_PATH", str(tmp_path / "panel.conf"))
    monkeypatch.setattr(auth, "_tokens", {})
    monkeypatch.setattr(auth, "_failures", {})
    db.init_db()
    db.set_setting("auth", {
        "password_hash": auth.hash_password("admin"),
        "password_change_required": False
    })
    http = TestClient(app.app, client=("198.51.100.7", 43210))
    yield http
    http.close()
    if db._conn:
        db._conn.close()


def authed_headers(http):
    res = http.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert res.status_code == 200
    return {"Authorization": "Bearer " + res.json()["token"]}


def create_test_node(nid="n1", port=52001, protocol="socks5", group="default", status="online", ping=88):
    node = {
        "id": nid, "name": nid, "group": group, "port": port,
        "protocol": protocol, "entryProto": "mixed",
        "status": status, "ping": ping, "upTraffic": 1024, "downTraffic": 2048,
        "consecutiveFails": 0, "rawConfig": {"server": "1.2.3.4", "server_port": 1080}
    }
    db.create_node(node)
    return db.get_node(nid)


# ==================== 1. API 契约与异常传播测试 ====================

def test_convert_entry_apply_failure_retains_fields_and_reports_message(api_client, monkeypatch):
    route = next(r for r in app.app.routes if getattr(r, "path", None) == "/api/nodes/convert-entry")
    assert route.response_model is app.models.EntryConvertResponse
    headers = authed_headers(api_client)
    create_test_node("c1", 52001, "socks5")

    # 1.1 异常情况：apply_config 抛出异常
    monkeypatch.setattr(
        app.config_manager, "apply_config",
        AsyncMock(side_effect=RuntimeError("singbox reload failed: port occupied"))
    )
    res = api_client.post(
        "/api/nodes/convert-entry",
        headers=headers,
        json={"ids": ["c1"], "entryProto": "ss", "ssPass": "secret123"}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["ok"] is True
    assert data["converted"] == 1
    assert data["configApplied"] is False
    assert "singbox reload failed: port occupied" in data["configMessage"]

    # 1.2 成功情况：apply_config 正常执行
    monkeypatch.setattr(
        app.config_manager, "apply_config",
        AsyncMock(return_value={"ok": True, "message": "配置热重载已生效"})
    )
    res2 = api_client.post(
        "/api/nodes/convert-entry",
        headers=headers,
        json={"ids": ["c1"], "entryProto": "mixed"}
    )
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    assert data2["ok"] is True
    assert data2["converted"] == 1
    assert data2["configApplied"] is True
    assert data2["configMessage"] == "配置热重载已生效"


def test_batch_group_apply_failure_retains_fields_and_reports_message(api_client, monkeypatch):
    headers = authed_headers(api_client)
    create_test_node("bg1", 52002, "socks5", group="groupA")
    create_test_node("bg2", 52003, "socks5", group="groupA")

    # 2.1 异常情况：apply_config 抛出异常
    monkeypatch.setattr(
        app.config_manager, "apply_config",
        AsyncMock(side_effect=RuntimeError("singbox crashed on reload"))
    )
    res = api_client.post(
        "/api/nodes/batch-group",
        headers=headers,
        json={"ids": ["bg1", "bg2"], "group": "groupB"}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["ok"] is True
    assert data["updated"] == 2
    assert data["configApplied"] is False
    assert "singbox crashed on reload" in data["configMessage"]

    # 2.2 成功情况
    monkeypatch.setattr(
        app.config_manager, "apply_config",
        AsyncMock(return_value={"ok": True, "message": "配置已生效"})
    )
    res2 = api_client.post(
        "/api/nodes/batch-group",
        headers=headers,
        json={"ids": ["bg1"], "group": "groupC"}
    )
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    assert data2["ok"] is True
    assert data2["updated"] == 1
    assert data2["configApplied"] is True
    assert data2["configMessage"] == "配置已生效"


def test_rename_group_apply_failure_retains_fields_and_reports_message(api_client, monkeypatch):
    headers = authed_headers(api_client)
    create_test_node("rg1", 52004, "socks5", group="oldG")

    # 3.1 异常情况：apply_config 抛出异常
    monkeypatch.setattr(
        app.config_manager, "apply_config",
        AsyncMock(side_effect=RuntimeError("config validation syntax error"))
    )
    res = api_client.post(
        "/api/groups/rename",
        headers=headers,
        json={"oldName": "oldG", "newName": "newG"}
    )
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["ok"] is True
    assert data["updated"] == 1
    assert data["configApplied"] is False
    assert "config validation syntax error" in data["configMessage"]

    # 3.2 成功情况
    monkeypatch.setattr(
        app.config_manager, "apply_config",
        AsyncMock(return_value={"ok": True, "message": "配置已生效"})
    )
    res2 = api_client.post(
        "/api/groups/rename",
        headers=headers,
        json={"oldName": "newG", "newName": "finalG"}
    )
    assert res2.status_code == 200, res2.text
    data2 = res2.json()
    assert data2["ok"] is True
    assert data2["updated"] == 1
    assert data2["configApplied"] is True
    assert data2["configMessage"] == "配置已生效"


def test_settings_relay_failure_rolls_back_and_skips_apply(api_client, monkeypatch):
    headers = authed_headers(api_client)
    old_relay = {"id": "old", "domain": "old.example", "port": 51001, "groups": ["ALL"]}
    db.set_system_settings({"relayDomains": [old_relay], "offlineGraceFails": 2})
    previous = db.get_setting("system")
    previous_relays = db.list_relay_domains()
    conn = db.connect()
    conn.execute("CREATE TRIGGER fail_relay BEFORE INSERT ON relay_domains BEGIN SELECT RAISE(ABORT, 'forced failure'); END")
    conn.commit()
    apply = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(app.config_manager, "apply_config", apply)
    with pytest.raises(sqlite3.IntegrityError):
        api_client.put("/api/settings", headers=headers, json={
            "offlineGraceFails": 3,
            "relayDomains": [{"id": "new", "domain": "new.example", "port": 51002}],
        })
    assert db.get_setting("system") == previous
    assert db.list_relay_domains() == previous_relays
    assert not conn.in_transaction
    apply.assert_not_awaited()


def test_query_token_only_works_for_stats_stream(api_client):
    from starlette.requests import Request
    token = authed_headers(api_client)["Authorization"].removeprefix("Bearer ")
    assert api_client.get("/api/nodes", params={"token": token}).status_code == 401
    req = Request({"type": "http", "method": "GET", "path": "/api/stats/stream",
                   "query_string": ("token=" + token).encode(), "headers": []})
    app.require_auth(req)
    response = api_client.options("/api/nodes", headers={"Origin": "https://other.example",
        "Access-Control-Request-Method": "GET", "Access-Control-Request-Headers": "authorization"})
    assert "access-control-allow-origin" not in response.headers


@pytest.mark.parametrize("batch", [False, True])
def test_delete_fingerprint_failure_rolls_back(api_client, batch):
    create_test_node("deleted", 52031)
    conn = db.connect()
    conn.execute("UPDATE nodes SET sub_id=? WHERE id=?", ("sub1", "deleted"))
    conn.execute("CREATE TRIGGER fail_mark BEFORE INSERT ON deleted_fingerprints BEGIN SELECT RAISE(ABORT, 'forced mark failure'); END")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        if batch:
            db.delete_node_batch(["deleted"])
        else:
            db.delete_node("deleted")
    assert not conn.in_transaction
    db.set_setting("other", {"commit": True})
    assert db.get_node("deleted") is not None


def test_rename_group_failure_rolls_back(api_client):
    create_test_node("grouped", 52032, group="old")
    db.set_system_settings({"relayDomains": [{"id": "relay", "domain": "x.example", "port": 51031, "groups": ["old"]}]})
    conn = db.connect()
    conn.execute("CREATE TRIGGER fail_group BEFORE UPDATE ON relay_domains BEGIN SELECT RAISE(ABORT, 'forced group failure'); END")
    conn.commit()
    with pytest.raises(sqlite3.IntegrityError):
        db.rename_group("old", "new")
    assert not conn.in_transaction
    db.set_setting("other", {"commit": True})
    assert db.get_node("grouped")["group"] == "old"
    assert db.list_relay_domains()[0]["groups"] == ["old"]


# ==================== 2. 设置中 offlineGraceFails 校验测试 ====================

def test_settings_put_rejects_invalid_offline_grace_fails(api_client, monkeypatch):
    headers = authed_headers(api_client)
    monkeypatch.setattr(app.config_manager, "apply_config", AsyncMock(return_value={"ok": True}))

    # 0 拒绝
    r0 = api_client.put("/api/settings", headers=headers, json={"offlineGraceFails": 0})
    assert r0.status_code == 422
    assert "offlineGraceFails 必须在 1..=10 范围内" in r0.json()["detail"]

    # 11 拒绝
    r11 = api_client.put("/api/settings", headers=headers, json={"offlineGraceFails": 11})
    assert r11.status_code == 422
    assert "offlineGraceFails 必须在 1..=10 范围内" in r11.json()["detail"]

    # 非整数拒绝
    r_str = api_client.put("/api/settings", headers=headers, json={"offlineGraceFails": "invalid"})
    assert r_str.status_code == 422
    assert "必须是整数" in r_str.json()["detail"]

    # 合法值 3 接受并存盘
    r_ok = api_client.put("/api/settings", headers=headers, json={"offlineGraceFails": 3})
    assert r_ok.status_code == 200
    assert r_ok.json()["configApplied"] is True

    # GET 接口返回该字段
    r_get = api_client.get("/api/settings", headers=headers)
    assert r_get.status_code == 200
    assert r_get.json()["offlineGraceFails"] == 3


# ==================== 3. scheduler parse_offline_grace_fails 单元逻辑 ====================

def test_parse_offline_grace_fails_logic():
    assert s.parse_offline_grace_fails(None) == 2
    assert s.parse_offline_grace_fails(True) == 2
    assert s.parse_offline_grace_fails(False) == 2
    assert s.parse_offline_grace_fails(0) == 2
    assert s.parse_offline_grace_fails(1) == 1
    assert s.parse_offline_grace_fails(2) == 2
    assert s.parse_offline_grace_fails(5) == 5
    assert s.parse_offline_grace_fails(10) == 10
    assert s.parse_offline_grace_fails(11) == 2
    assert s.parse_offline_grace_fails("3") == 3
    assert s.parse_offline_grace_fails(" 7 ") == 7
    assert s.parse_offline_grace_fails("0") == 2
    assert s.parse_offline_grace_fails("12") == 2
    assert s.parse_offline_grace_fails("invalid") == 2
    assert s.parse_offline_grace_fails([]) == 2
    assert s.parse_offline_grace_fails({}) == 2


# ==================== 4. scheduler offlineGraceFails 探活逻辑 ====================

class TestSchedulerOfflineGrace(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="grace-reg-")
        self.old_conn = db._conn
        db._conn = None
        self.patchers = [
            patch.object(db, "DATA_DIR", self.tmp.name),
            patch.object(db, "DB_PATH", str(Path(self.tmp.name) / "panel.db")),
            patch.object(cm, "is_running", lambda: True),
            patch.object(cm, "get_clash_secret", lambda: "sec"),
            patch.object(cm, "apply_config", AsyncMock(return_value={"ok": True})),
            patch.object(s, "_lazy_enrich_ip", Mock()),
        ]
        for p in self.patchers:
            p.start()
        db.init_db()

    async def asyncTearDown(self):
        for p in reversed(self.patchers):
            p.stop()
        if db._conn:
            db._conn.close()
        self.tmp.cleanup()

    async def test_background_probe_grace_keeps_online_and_ping(self):
        # 默认 offlineGraceFails = 2
        db.set_setting("system", {"offlineGraceFails": 2})
        create_test_node("n_grace", 52010, "socks5", status="online", ping=88)

        fail_res = {"id": "n_grace", "tag": cm.outbound_tag("socks5", 52010),
                    "ping": 0, "status": "offline", "error": "timeout"}
        with patch.object(s, "_probe_one", AsyncMock(side_effect=lambda *a, **kw: dict(fail_res))):
            # 第 1 轮后台探活失败：容差期内 (fails=1 < grace=2)
            res1 = await s.probe_nodes(ids=["n_grace"], manual=False)
            assert len(res1) == 1
            assert res1[0]["status"] == "online"
            assert res1[0]["ping"] == 88
            assert "未达离线容差 2 次，保持在线" in res1[0]["error"]

            node1 = db.get_node("n_grace")
            assert node1["status"] == "online"
            assert node1["ping"] == 88
            assert node1["consecutiveFails"] == 1
            assert node1["upTraffic"] == 1024
            assert node1["downTraffic"] == 2048

            # 第 2 轮后台探活失败：达到容差 (fails=2 >= grace=2)
            res2 = await s.probe_nodes(ids=["n_grace"], manual=False)
            assert len(res2) == 1
            assert res2[0]["status"] == "offline"

            node2 = db.get_node("n_grace")
            assert node2["status"] == "offline"
            assert node2["consecutiveFails"] == 2
            assert node2["upTraffic"] == 1024
            assert node2["downTraffic"] == 2048

    async def test_manual_probe_fails_immediately(self):
        db.set_setting("system", {"offlineGraceFails": 2})
        create_test_node("n_manual", 52011, "socks5", status="online", ping=99)

        fail_res = {"id": "n_manual", "tag": cm.outbound_tag("socks5", 52011),
                    "ping": 0, "status": "offline", "error": "manual fail"}
        with patch.object(s, "_probe_one", AsyncMock(side_effect=lambda *a, **kw: dict(fail_res))):
            # Manual 探活：立即失败，不进容差
            res = await s.probe_nodes(ids=["n_manual"], manual=True)
            assert len(res) == 1
            assert res[0]["status"] == "offline"

            node = db.get_node("n_manual")
            assert node["status"] == "offline"

    async def test_already_offline_node_fails_without_grace(self):
        db.set_setting("system", {"offlineGraceFails": 2})
        create_test_node("n_off", 52012, "socks5", status="offline", ping=0)

        fail_res = {"id": "n_off", "tag": cm.outbound_tag("socks5", 52012),
                    "ping": 0, "status": "offline", "error": "offline fail"}
        with patch.object(s, "_probe_one", AsyncMock(side_effect=lambda *a, **kw: dict(fail_res))):
            res = await s.probe_nodes(ids=["n_off"], manual=False)
            assert len(res) == 1
            assert res[0]["status"] == "offline"

            node = db.get_node("n_off")
            assert node["status"] == "offline"
            assert node["consecutiveFails"] == 1
