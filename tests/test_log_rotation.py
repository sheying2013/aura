"""日志上限回归：只测试本地临时文件，不启动 sing-box 或容器。"""
import asyncio
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))
import config_manager


def test_open_log_truncates_historic_oversize_file(tmp_path, monkeypatch):
    path = tmp_path / "singbox.log"
    path.write_bytes(b"x" * 11)
    monkeypatch.setattr(config_manager, "LOG_PATH", str(path))
    monkeypatch.setattr(config_manager, "LOG_MAX_BYTES", 10)
    config_manager._logf = None

    config_manager._open_log()
    try:
        assert path.stat().st_size == 0
    finally:
        config_manager._logf.close()
        config_manager._logf = None


def test_log_reader_rotates_bounded_backups(tmp_path, monkeypatch):
    path = tmp_path / "singbox.log"
    monkeypatch.setattr(config_manager, "LOG_PATH", str(path))
    monkeypatch.setattr(config_manager, "LOG_MAX_BYTES", 10)
    monkeypatch.setattr(config_manager, "LOG_BACKUP_COUNT", 3)
    config_manager._logf = open(path, "ab", buffering=0)

    class Reader:
        def __init__(self):
            self.chunks = [b"1234567890", b"abcdefghij", b"K"]

        async def read(self, _size):
            return self.chunks.pop(0) if self.chunks else b""

    try:
        asyncio.run(config_manager._log_reader(Reader()))
        assert path.read_bytes() == b"K"
        assert (tmp_path / "singbox.log.1").read_bytes() == b"abcdefghij"
        assert (tmp_path / "singbox.log.2").read_bytes() == b"1234567890"
        assert not (tmp_path / "singbox.log.3").exists()
    finally:
        if config_manager._logf is not None:
            config_manager._logf.close()
            config_manager._logf = None


def test_deploy_script_limits_docker_json_logs():
    script = Path(__file__).resolve().parents[1].joinpath("deploy.sh").read_text()
    assert "--log-driver json-file" in script
    assert "--log-opt max-size=10m" in script
    assert "--log-opt max-file=3" in script
