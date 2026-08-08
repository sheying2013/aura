"""面板级配置：端口 / 网页登录路径 / 登录用户名。

持久化到 data/panel.conf（JSON），供多方共用：
- app.py    读取 PANEL_PATH（网页路径前缀）与端口
- auth.py   读取登录用户名（默认 admin）
- start.sh  读取 uvicorn 端口
- aura CLI  交互式读写（面板端口/路径/账号/更新）

密码不在此文件——存 db settings 表（auth.password_hash）。
"""
import json
import os

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONF_PATH = os.path.join(BASE_DIR, "data", "panel.conf")

_DEFAULTS = {
    "port": 19001,
    "panel_path": "/admin",
    "username": "admin",
}


def _load() -> dict:
    try:
        with open(CONF_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except (OSError, json.JSONDecodeError):
        data = {}
    out = dict(_DEFAULTS)
    out.update({k: v for k, v in data.items() if k in _DEFAULTS and v is not None})
    return out


def get(key: str):
    """读单个配置项（带默认值）。"""
    return _load().get(key)


def set_many(items: dict) -> dict:
    """写多个配置项并持久化。仅接受已知键，避免脏数据。"""
    data = _load()
    for k, v in items.items():
        if k in _DEFAULTS and v is not None:
            data[k] = v
    os.makedirs(os.path.dirname(CONF_PATH), exist_ok=True)
    tmp = CONF_PATH + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, CONF_PATH)
    return data


def show() -> dict:
    """读取全部配置（含默认值）。"""
    return _load()
