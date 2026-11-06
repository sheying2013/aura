"""Tests for AURA_DATA_DIR override in backend/db.py and backend/panel_config.py."""
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"


class DataDirIsolatedImportTests(unittest.TestCase):
    def test_default_data_dir_when_aura_data_dir_unset(self):
        code = (
            "import os, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import db, panel_config\n"
            "expected_data = os.path.abspath(os.path.join(sys.argv[1], 'data'))\n"
            "expected_db = os.path.join(expected_data, 'panel.db')\n"
            "expected_conf = os.path.join(expected_data, 'panel.conf')\n"
            "assert db.DATA_DIR == expected_data, f'db.DATA_DIR mismatch: {db.DATA_DIR}'\n"
            "assert db.DB_PATH == expected_db, f'db.DB_PATH mismatch: {db.DB_PATH}'\n"
            "assert panel_config.CONF_PATH == expected_conf, f'panel_config.CONF_PATH mismatch: {panel_config.CONF_PATH}'\n"
            "print('OK')\n"
        )
        env = os.environ.copy()
        env.pop("AURA_DATA_DIR", None)
        res = subprocess.run(
            [sys.executable, "-c", code, str(BACKEND)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("OK", res.stdout)

    def test_custom_data_dir_when_aura_data_dir_set(self):
        with tempfile.TemporaryDirectory(prefix="aura_custom_data_") as tmp:
            custom_dir = str(Path(tmp).resolve() / "custom_data")
            code = (
                "import os, sys\n"
                "sys.path.insert(0, sys.argv[1])\n"
                "import db, panel_config, config_manager, app\n"
                "expected_data = os.path.abspath(sys.argv[2])\n"
                "expected_db = os.path.join(expected_data, 'panel.db')\n"
                "expected_conf = os.path.join(expected_data, 'panel.conf')\n"
                "assert db.DATA_DIR == expected_data, f'db.DATA_DIR mismatch: {db.DATA_DIR}'\n"
                "assert db.DB_PATH == expected_db, f'db.DB_PATH mismatch: {db.DB_PATH}'\n"
                "assert panel_config.CONF_PATH == expected_conf, f'panel_config.CONF_PATH mismatch: {panel_config.CONF_PATH}'\n"
                "assert config_manager.DATA_DIR == expected_data\n"
                "assert config_manager.CONFIG_PATH == os.path.join(expected_data, 'config.json')\n"
                "assert config_manager.LOG_PATH == os.path.join(expected_data, 'singbox.log')\n"
                "assert app.DATA_DIR == expected_data\n"
                "db.init_db()\n"
                "assert os.path.exists(expected_db), 'db file was not created in custom data dir'\n"
                "panel_config.set_many({'port': 29001})\n"
                "assert os.path.exists(expected_conf), 'panel.conf was not created in custom data dir'\n"
                "assert panel_config.get('port') == 29001\n"
                "print('OK')\n"
            )
            env = os.environ.copy()
            env["AURA_DATA_DIR"] = custom_dir
            res = subprocess.run(
                [sys.executable, "-c", code, str(BACKEND), custom_dir],
                env=env,
                capture_output=True,
                text=True,
            )
            self.assertEqual(res.returncode, 0, res.stderr)
            self.assertIn("OK", res.stdout)

    def test_empty_string_aura_data_dir_falls_back_to_default(self):
        code = (
            "import os, sys\n"
            "sys.path.insert(0, sys.argv[1])\n"
            "import db, panel_config\n"
            "expected_data = os.path.abspath(os.path.join(sys.argv[1], 'data'))\n"
            "assert db.DATA_DIR == expected_data, f'db.DATA_DIR mismatch: {db.DATA_DIR}'\n"
            "print('OK')\n"
        )
        env = os.environ.copy()
        env["AURA_DATA_DIR"] = ""
        res = subprocess.run(
            [sys.executable, "-c", code, str(BACKEND)],
            env=env,
            capture_output=True,
            text=True,
        )
        self.assertEqual(res.returncode, 0, res.stderr)
        self.assertIn("OK", res.stdout)


if __name__ == "__main__":
    unittest.main()
