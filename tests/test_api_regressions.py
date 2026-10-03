"""API 边界回归：临时 DB，不启动 lifespan 或代理内核。"""
import asyncio
import sys
from pathlib import Path
from unittest.mock import AsyncMock

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import app
import auth
import db
import panel_config


@pytest.fixture
def api_client(tmp_path, monkeypatch):
    # 不使用 with TestClient，以免触发应用 startup / shutdown。
    monkeypatch.delenv("AUTH_DISABLED", raising=False)
    monkeypatch.setattr(db, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(db, "DB_PATH", str(tmp_path / "panel.db"))
    monkeypatch.setattr(db, "_conn", None)
    monkeypatch.setattr(panel_config, "CONF_PATH", str(tmp_path / "panel.conf"))
    monkeypatch.setattr(auth, "_tokens", {})
    monkeypatch.setattr(auth, "_failures", {})
    db.init_db()
    http = TestClient(app.app, client=("198.51.100.7", 43210))
    yield http
    http.close()
    if db._conn:
        db._conn.close()


def login(http):
    response = http.post("/api/auth/login", json={"username": "admin", "password": "admin"})
    assert response.status_code == 200
    return response.json()


def test_initial_password_session_is_limited(api_client):
    session = login(api_client)
    assert session["passwordChangeRequired"]
    headers = {"Authorization": "Bearer " + session["token"]}
    assert api_client.get("/api/auth/check", headers=headers).status_code == 200
    assert api_client.get("/api/auth/status", headers=headers).json()["passwordChangeRequired"]
    assert api_client.get("/api/nodes", headers=headers).status_code == 403
    payload = {"name": "test", "protocol": "socks", "port": 53001,
               "rawConfig": {"server": "example.test", "server_port": 443}}
    assert api_client.post("/api/nodes", headers=headers, json=payload).status_code == 403
    assert db.list_nodes() == []
    response = api_client.post("/api/auth/change-password", headers=headers,
                               json={"oldPassword": "admin", "newPassword": "new-password"})
    assert response.status_code == 200
    assert api_client.get("/api/nodes", headers=headers).status_code == 401
    updated = {"Authorization": "Bearer " + response.json()["token"]}
    assert api_client.post("/api/nodes", headers=updated, json=payload).status_code == 201


def test_xff_does_not_control_failure_bucket(api_client, monkeypatch):
    monkeypatch.setattr(auth.asyncio, "sleep", AsyncMock())
    for value in ["8.8.8.8", "9.9.9.9"]:
        response = api_client.post("/api/auth/login", headers={"X-Forwarded-For": value},
                                   json={"username": "admin", "password": "wrong"})
        assert response.status_code == 401
    assert set(auth._failures) == {"198.51.100.7"}
    assert len(auth._failures["198.51.100.7"]) == 1


def test_ping_api_cannot_trigger_background_penalties(api_client, monkeypatch):
    db.set_setting("auth", {"password_hash": auth.hash_password("admin"),
                            "password_change_required": False})
    session = login(api_client)
    probe = AsyncMock(return_value=[])
    monkeypatch.setattr(app.scheduler, "probe_nodes", probe)
    response = api_client.post("/api/nodes/ping",
                               headers={"Authorization": "Bearer " + session["token"]},
                               json={"all": True, "manual": False})
    assert response.status_code == 200
    assert probe.await_args.kwargs["manual"] is True


def test_partial_settings_preserve_unsent_keys(api_client, monkeypatch):
    db.set_setting("auth", {"password_hash": auth.hash_password("admin"),
                            "password_change_required": False})
    db.set_setting("system", {"autoRefresh": False, "stickyEnabled": True,
                              "relayDomains": [], "probeInterval": 60})
    headers = {"Authorization": "Bearer " + login(api_client)["token"]}
    monkeypatch.setattr(app.config_manager, "apply_config", AsyncMock(return_value={"ok": True}))
    response = api_client.put("/api/settings", headers=headers, json={"logLevel": "debug"})
    assert response.status_code == 200
    saved = db.get_setting("system")
    assert saved["autoRefresh"] is False
    assert saved["stickyEnabled"] is True
    assert saved["logLevel"] == "debug"


def test_invalid_relay_settings_do_not_overwrite_data(api_client, monkeypatch):
    db.set_setting("auth", {"password_hash": auth.hash_password("admin"),
                            "password_change_required": False})
    old = {"relayDomains": [{"id": "old", "domain": "relay.test", "port": 33440}]}
    db.set_setting("system", old)
    db.upsert_relay_domains(old["relayDomains"])
    headers = {"Authorization": "Bearer " + login(api_client)["token"]}
    applied = AsyncMock(return_value={"ok": True})
    monkeypatch.setattr(app.config_manager, "apply_config", applied)
    duplicate = [{"id": "a", "domain": "one.test", "port": 33441},
                 {"id": "b", "domain": "two.test", "port": 33441}]
    response = api_client.put("/api/settings", headers=headers, json={"relayDomains": duplicate})
    assert response.status_code == 409
    assert db.get_setting("system") == old
    assert [r["id"] for r in db.list_relay_domains()] == ["old"]
    applied.assert_not_awaited()
    response = api_client.put("/api/settings", headers=headers, json={"relayDomains": []})
    assert response.status_code == 200
    assert db.list_relay_domains() == []



def test_shutdown_cancels_background_tasks(monkeypatch, tmp_path):
    monkeypatch.setattr(app, "DATA_DIR", str(tmp_path))
    monkeypatch.setattr(app, "STATIC_DIR", str(tmp_path))
    monkeypatch.setattr(db, "init_db", lambda: None)
    monkeypatch.setattr(db, "get_setting", lambda *args: {})
    monkeypatch.setattr(app.config_manager, "CONFIG_PATH", str(tmp_path / "missing"))
    monkeypatch.setattr(app.config_manager, "CONFIG_BAK_PATH", str(tmp_path / "missing-bak"))
    monkeypatch.setattr(app.scheduler, "start_scheduler", lambda loop: None)
    monkeypatch.setattr(app.stats, "start_tasks", lambda loop: None)
    stop_scheduler, stop_stats, stop_core = AsyncMock(), AsyncMock(), AsyncMock()
    monkeypatch.setattr(app.scheduler, "stop_scheduler", stop_scheduler)
    monkeypatch.setattr(app.stats, "stop_tasks", stop_stats)
    monkeypatch.setattr(app.config_manager, "stop", stop_core)

    async def exercise():
        async with app.lifespan(app.app):
            pass

    asyncio.run(exercise())
    stop_scheduler.assert_awaited_once()
    stop_stats.assert_awaited_once()
    stop_core.assert_awaited_once()
