"""Run deploy.sh with local Docker/curl/sleep doubles; no network or containers."""
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DeployRegressionTests(unittest.TestCase):
    def deploy(self, *, stored=None, override=None, probe_code="200"):
        with tempfile.TemporaryDirectory(prefix="aura deploy ") as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            # Prevent the legacy migration path from touching any real local database.
            (data / "panel.db").write_text("local fixture")
            conf = data / "panel.conf"
            if stored is not None:
                conf.write_text(json.dumps(stored))
            before = conf.read_bytes() if conf.exists() else None
            log = root / "calls.jsonl"
            bin_dir = root / "bin"
            bin_dir.mkdir()
            common = (
                "import json, os, sys\nfrom pathlib import Path\n"
                "with open(os.environ['MOCK_LOG'], 'a') as f:\n"
                "    f.write(json.dumps([Path(sys.argv[0]).name, *sys.argv[1:]]) + '\\n')\n"
            )
            programs = {
                "docker": common +
                    "if sys.argv[1:3] == ['run', '--rm']:\n"
                    "    assert sys.argv[3:5] == ['--entrypoint', 'python']\n"
                    "    mount = sys.argv[sys.argv.index('-v') + 1]\n"
                    "    assert mount == os.environ['AURA_DATA_DIR'] + ':/app/backend/data'\n"
                    "    import importlib.util\n"
                    "    spec = importlib.util.spec_from_file_location('panel_config', os.environ['PANEL_MODULE'])\n"
                    "    module = importlib.util.module_from_spec(spec)\n"
                    "    spec.loader.exec_module(module)\n"
                    "    module.CONF_PATH = str(Path(os.environ['AURA_DATA_DIR']) / 'panel.conf')\n"
                    "    sys.modules['panel_config'] = module\n"
                    "    key, value = sys.argv[sys.argv.index('-e') + 1].split('=', 1)\n"
                    "    os.environ[key] = value\n"
                    "    exec(sys.argv[sys.argv.index('-c') + 1], {'__name__': '__main__'})\n"
                    "elif sys.argv[1:3] == ['run', '-d']:\n"
                    "    print('mock-container-id')\n",
                "curl": common + "print(os.environ['PROBE_CODE'], end='')\n",
                "sleep": common,
            }
            for name, body in programs.items():
                path = bin_dir / name
                path.write_text(f"#!{sys.executable}\n" + body)
                path.chmod(0o755)
            env = os.environ.copy()
            for key in list(env):
                if key.startswith("AURA_"):
                    del env[key]
            env.update({
                "AURA_DATA_DIR": str(data), "MOCK_LOG": str(log),
                "PANEL_MODULE": str(ROOT / "backend/panel_config.py"),
                "PROBE_CODE": probe_code,
                "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            })
            if override is not None:
                env["AURA_PORT"] = override
            result = subprocess.run(
                ["bash", str(ROOT / "deploy.sh")], env=env, cwd=root,
                capture_output=True, text=True, timeout=10,
            )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            after = conf.read_bytes() if conf.exists() else None
            return result, calls, before, after, list(data.glob("*.tmp"))

    def test_existing_port_and_custom_path_control_probe_and_print(self):
        stored = {"port": 28080, "panel_path": "/private-panel", "username": "owner"}
        result, calls, before, after, _ = self.deploy(stored=stored)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, after, "Deployment without override must not rewrite configuration")
        probe = next(call for call in calls if call[0] == "curl")
        self.assertEqual(probe[-1], "http://127.0.0.1:28080/private-panel/")
        self.assertIn("http://<服务器IP>:28080/private-panel", result.stdout)
        self.assertEqual([call[1] for call in calls if call[0] == "docker"], ["pull", "run", "rm", "run"])

    def test_explicit_port_is_persisted_without_changing_path_or_username(self):
        stored = {"port": 28080, "panel_path": "/custom", "username": "owner"}
        result, calls, _, after, tmp_files = self.deploy(stored=stored, override="30080")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(after), {**stored, "port": 30080})
        self.assertEqual(tmp_files, [], "Atomic config write must not leave a temporary file")
        self.assertEqual(next(call for call in calls if call[0] == "curl")[-1], "http://127.0.0.1:30080/custom/")
        self.assertIn("http://<服务器IP>:30080/custom", result.stdout)

    def test_invalid_explicit_port_does_not_stop_old_container_or_write_config(self):
        for value in ("0", "65536", "abc", "80/evil", "-1", " 8080", "8.5"):
            with self.subTest(value=value):
                result, calls, before, after, _ = self.deploy(
                    stored={"port": 28080, "panel_path": "/custom", "username": "owner"},
                    override=value,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("端口不合法", result.stderr)
                self.assertEqual(before, after)
                self.assertFalse(any(call[0] == "docker" and call[1] == "rm" for call in calls))
                self.assertFalse(any(call[0] == "curl" for call in calls))
                self.assertFalse(any(call[:3] == ["docker", "run", "-d"] for call in calls))

    def test_fresh_install_uses_default_port_and_path_without_writing_config(self):
        result, calls, before, after, _ = self.deploy()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIsNone(before)
        self.assertIsNone(after)
        self.assertEqual(next(call for call in calls if call[0] == "curl")[-1], "http://127.0.0.1:19001/admin/")
        self.assertIn("http://<服务器IP>:19001/admin", result.stdout)

    def test_empty_override_preserves_stored_port(self):
        result, calls, before, after, _ = self.deploy(
            stored={"port": 28080, "panel_path": "/admin", "username": "owner"}, override="",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, after)
        self.assertEqual(next(call for call in calls if call[0] == "curl")[-1], "http://127.0.0.1:28080/admin/")

    def test_failed_probe_reports_logs_and_does_not_print_success(self):
        result, calls, _, _, _ = self.deploy(probe_code="503")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(["docker", "logs", "--tail", "20", "aura-panel"], calls)
        self.assertNotIn("更新完成", result.stdout)


if __name__ == "__main__":
    unittest.main()
