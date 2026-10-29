"""Run deploy.sh with local Docker/curl/sleep doubles; no network or containers."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class DeployRegressionTests(unittest.TestCase):
    def deploy(self, *, stored=None, override=None, probe_code="200", old_image=None, fail_run=False, fail_old_run=False, fail_discovery=None, fail_rm=False, signal_at_sleep=False, conf_mode=None):
        with tempfile.TemporaryDirectory(prefix="aura deploy ") as tmp:
            root = Path(tmp)
            data = root / "data"
            data.mkdir()
            # Prevent the legacy migration path from touching any real local database.
            (data / "panel.db").write_text("local fixture")
            conf = data / "panel.conf"
            if stored is not None:
                conf.write_text(json.dumps(stored))
                if conf_mode is not None:
                    conf.chmod(conf_mode)
            before = conf.read_bytes() if conf.exists() else None
            before_mode = conf.stat().st_mode if conf.exists() else None
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
                    "    assert sys.argv[3:5] == ['--entrypoint', '/app/backend/aura']\n"
                    "    mount = sys.argv[sys.argv.index('-v') + 1]\n"
                    "    host_dir, target = mount.split(':', 1)\n"
                    "    assert host_dir == os.environ['AURA_DATA_DIR']\n"
                    "    assert target == '/app/backend/data'\n"
                    "    key, value = sys.argv[sys.argv.index('-e') + 1].split('=', 1)\n"
                    "    assert (key, value) == ('AURA_DATA_DIR', '/app/backend/data')\n"
                    "    args = sys.argv[sys.argv.index('panel-config') + 1:]\n"
                    "    if len(args) > 1:\n"
                    "        print('用法: aura panel-config [PORT]', file=sys.stderr)\n"
                    "        raise SystemExit(1)\n"
                    "    conf = Path(host_dir) / 'panel.conf'\n"
                    "    settings = json.loads(conf.read_text()) if conf.exists() else {'port': 19001, 'panel_path': '/admin', 'username': 'admin'}\n"
                    "    path = settings.get('panel_path') or '/admin'\n"
                    "    if not path.startswith('/') or any(ch.isspace() for ch in path):\n"
                    "        print('面板登录路径不合法', file=sys.stderr)\n"
                    "        raise SystemExit(1)\n"
                    "    if args:\n"
                    "        raw = args[0]\n"
                    "        if not raw or not raw.isascii() or not raw.isdigit() or not 1 <= int(raw) <= 65535:\n"
                    "            print('面板端口不合法，应为 1-65535 的整数', file=sys.stderr)\n"
                    "            raise SystemExit(1)\n"
                    "        settings['port'] = int(raw)\n"
                    "        tmp = conf.with_name(conf.name + '.tmp')\n"
                    "        tmp.write_text(json.dumps(settings))\n"
                    "        os.replace(tmp, conf)\n"
                    "    print(str(settings.get('port') or 19001) + '\\n' + path)\n"
                    "elif sys.argv[1:2] == ['ps']:\n"
                    "    assert sys.argv[2:3] == ['-aq']\n"
                    "    if os.environ.get('MOCK_FAIL_DISCOVERY') == 'ps':\n"
                    "        print('docker daemon unavailable', file=sys.stderr)\n"
                    "        sys.exit(1)\n"
                    "    if os.environ.get('MOCK_OLD_IMAGE'):\n"
                    "        print('mock-container-id')\n"
                    "elif sys.argv[1:2] == ['inspect']:\n"
                    "    assert sys.argv[2:4] == ['-f', '{{.Image}}']\n"
                    "    if os.environ.get('MOCK_FAIL_DISCOVERY') == 'inspect':\n"
                    "        print('docker inspect failed', file=sys.stderr)\n"
                    "        sys.exit(1)\n"
                    "    old_img = os.environ.get('MOCK_OLD_IMAGE', '')\n"
                    "    if old_img:\n"
                    "        print(old_img)\n"
                    "    else:\n"
                    "        print('Error: No such container: ' + sys.argv[4], file=sys.stderr)\n"
                    "        sys.exit(1)\n"
                    "elif sys.argv[1:3] == ['run', '-d']:\n"
                    "    if os.environ.get('MOCK_FAIL_RUN') and sys.argv[-1] == 'ghcr.io/sheying2013/aura:latest':\n"
                    "        print('docker: Error response from daemon: failed to start', file=sys.stderr)\n"
                    "        sys.exit(1)\n"
                    "    if os.environ.get('MOCK_FAIL_OLD_RUN') and sys.argv[-1] == os.environ.get('MOCK_OLD_IMAGE'):\n"
                    "        print('docker: failed to restore old image', file=sys.stderr)\n"
                    "        sys.exit(1)\n"
                    "    print('mock-container-id')\n"
                    "elif sys.argv[1:3] == ['rm', '-f']:\n"
                    "    if os.environ.get('MOCK_FAIL_RM'):\n"
                    "        print('docker: remove failed', file=sys.stderr)\n"
                    "        sys.exit(1)\n"
                    "elif sys.argv[1:3] == ['logs', '--tail']:\n"
                    "    print('mock logs')\n",
                "curl": common + "print(os.environ['PROBE_CODE'], end='')\n",
                "sleep": common +
                    "if os.environ.get('MOCK_BLOCK_SLEEP'):\n"
                    "    Path(os.environ['MOCK_SLEEP_MARKER']).write_text('started')\n"
                    "    import time\n"
                    "    while True:\n"
                    "        time.sleep(1)\n",
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
                "PROBE_CODE": probe_code,
                "PATH": str(bin_dir) + os.pathsep + env["PATH"],
            })
            if override is not None:
                env["AURA_PORT"] = override
            if old_image is not None:
                env["MOCK_OLD_IMAGE"] = old_image
            if fail_run:
                env["MOCK_FAIL_RUN"] = "1"
            if fail_old_run:
                env["MOCK_FAIL_OLD_RUN"] = "1"
            if fail_discovery is not None:
                env["MOCK_FAIL_DISCOVERY"] = fail_discovery
            if fail_rm:
                env["MOCK_FAIL_RM"] = "1"
            if signal_at_sleep:
                marker = root / "sleep-ready"
                env["MOCK_BLOCK_SLEEP"] = "1"
                env["MOCK_SLEEP_MARKER"] = str(marker)
                proc = subprocess.Popen(
                    ["bash", str(ROOT / "deploy.sh")], env=env, cwd=root,
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    start_new_session=True,
                )
                deadline = time.monotonic() + 5
                while not marker.exists() and proc.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.01)
                if not marker.exists():
                    if proc.poll() is None:
                        os.killpg(proc.pid, signal.SIGKILL)
                    proc.communicate(timeout=5)
                    raise AssertionError("deploy.sh never reached the health-check sleep")
                os.killpg(proc.pid, signal.SIGTERM)
                stdout, stderr = proc.communicate(timeout=10)
                result = subprocess.CompletedProcess(proc.args, proc.returncode, stdout, stderr)
            else:
                result = subprocess.run(
                    ["bash", str(ROOT / "deploy.sh")], env=env, cwd=root,
                    capture_output=True, text=True, timeout=10,
                )
            calls = [json.loads(line) for line in log.read_text().splitlines()]
            after = conf.read_bytes() if conf.exists() else None
            after_mode = conf.stat().st_mode if conf.exists() else None
            if conf_mode is not None and conf.exists():
                assert after_mode == before_mode, f"Mode mismatch: {oct(after_mode)} != {oct(before_mode)}"
            leftovers = [p.name for p in data.iterdir() if p.name.endswith(".tmp") or ".bak" in p.name]
            return result, calls, before, after, leftovers

    def test_existing_port_and_custom_path_control_probe_and_print(self):
        stored = {"port": 28080, "panel_path": "/private-panel", "username": "owner"}
        result, calls, before, after, _ = self.deploy(stored=stored)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(before, after, "Deployment without override must not rewrite configuration")
        probe = next(call for call in calls if call[0] == "curl")
        self.assertEqual(probe[-1], "http://127.0.0.1:28080/private-panel/")
        self.assertIn("http://<服务器IP>:28080/private-panel", result.stdout)
        self.assertEqual([call[1] for call in calls if call[0] == "docker"], ["pull", "run", "ps", "rm", "run"])

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

    def test_health_probe_failure_rolls_back_to_old_image_and_restores_config(self):
        stored = {"port": 28080, "panel_path": "/admin", "username": "admin"}
        old_image = "sha256:old-immutable-image-id-1234"
        result, calls, before, after, leftovers = self.deploy(
            stored=stored,
            override="30080",
            probe_code="503",
            old_image=old_image,
            conf_mode=0o600,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("更新完成", result.stdout)
        self.assertEqual(before, after, "Config must be restored to pre-override state on health failure")
        self.assertEqual(json.loads(after), stored)
        self.assertEqual(leftovers, [], "Rollback must not leave backup or temporary files")

        docker_calls = [call for call in calls if call[0] == "docker"]
        self.assertEqual([call[1] for call in docker_calls], ["pull", "run", "ps", "inspect", "rm", "run", "logs", "rm", "run"])

        first_run_d = [call for call in docker_calls if call[1] == "run" and "-d" in call][0]
        self.assertEqual(first_run_d[-1], "ghcr.io/sheying2013/aura:latest")

        second_run_d = [call for call in docker_calls if call[1] == "run" and "-d" in call][1]
        self.assertEqual(second_run_d[-1], old_image)
        self.assertIn(f"ROLLBACK_DONE old_image={old_image}", result.stdout)

    def test_container_start_failure_rolls_back_to_old_image_and_restores_config(self):
        stored = {"port": 28080, "panel_path": "/admin", "username": "admin"}
        old_image = "sha256:old-immutable-image-id-5678"
        result, calls, before, after, leftovers = self.deploy(
            stored=stored,
            override="30080",
            old_image=old_image,
            fail_run=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("更新完成", result.stdout)
        self.assertIn("新容器启动失败", result.stdout)
        self.assertEqual(before, after, "Config must be restored to pre-override state on container start failure")
        self.assertEqual(json.loads(after), stored)
        self.assertEqual(leftovers, [], "Rollback must not leave backup or temporary files")

        self.assertFalse(any(call[0] == "curl" for call in calls))

        docker_calls = [call for call in calls if call[0] == "docker"]
        self.assertEqual([call[1] for call in docker_calls], ["pull", "run", "ps", "inspect", "rm", "run", "rm", "run"])

        first_run_d = [call for call in docker_calls if call[1] == "run" and "-d" in call][0]
        self.assertEqual(first_run_d[-1], "ghcr.io/sheying2013/aura:latest")

        second_run_d = [call for call in docker_calls if call[1] == "run" and "-d" in call][1]
        self.assertEqual(second_run_d[-1], old_image)

    def test_no_old_container_cleans_up_failed_container_without_restarting(self):
        result, calls, before, after, leftovers = self.deploy(
            override="30080",
            probe_code="503",
            old_image=None,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertNotIn("更新完成", result.stdout)
        self.assertIn("无可回滚版本", result.stdout)
        self.assertIsNone(before)
        self.assertIsNone(after, "Newly created config must be removed when rolling back a fresh install")
        self.assertEqual(leftovers, [])

        docker_calls = [call for call in calls if call[0] == "docker"]
        run_d_calls = [call for call in docker_calls if call[1] == "run" and "-d" in call]
        self.assertEqual(len(run_d_calls), 1)
        self.assertEqual(run_d_calls[0][-1], "ghcr.io/sheying2013/aura:latest")

        rm_calls = [call for call in docker_calls if call[1] == "rm"]
        self.assertEqual(len(rm_calls), 2)

    def test_container_discovery_failure_preserves_old_container_and_config(self):
        stored = {"port": 28080, "panel_path": "/admin", "username": "admin"}
        for failure_stage in ("ps", "inspect"):
            with self.subTest(failure_stage=failure_stage):
                result, calls, before, after, leftovers = self.deploy(
                    stored=stored, override="30080", old_image="sha256:old-id",
                    fail_discovery=failure_stage,
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(before, after)
                self.assertEqual(json.loads(after), stored)
                self.assertEqual(leftovers, [])
                docker_calls = [call for call in calls if call[0] == "docker"]
                self.assertFalse(any(call[1] == "rm" for call in docker_calls))
                self.assertFalse(any(call[1] == "run" and "-d" in call for call in docker_calls))
                self.assertFalse(any(call[0] == "curl" for call in calls))

    def test_old_image_restore_failure_is_reported_without_false_success(self):
        old_image = "sha256:old-image-rollback-fails"
        result, calls, before, after, leftovers = self.deploy(
            stored={"port": 28080, "panel_path": "/admin", "username": "admin"},
            override="30080", probe_code="503", old_image=old_image, fail_old_run=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(f"ROLLBACK_FAILED old_image={old_image}", result.stderr)
        self.assertNotIn(f"ROLLBACK_DONE old_image={old_image}", result.stdout)
        self.assertEqual(before, after)
        self.assertEqual(leftovers, [])

    def test_failed_container_cleanup_is_reported_as_partial_rollback(self):
        old_image = "sha256:old-image-cleanup-fails"
        result, calls, before, after, leftovers = self.deploy(
            stored={"port": 28080, "panel_path": "/admin", "username": "admin"},
            override="30080", probe_code="503", old_image=old_image, fail_rm=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ROLLBACK_FAILED container_cleanup", result.stderr)
        self.assertIn("docker rm error: docker: remove failed", result.stderr)
        self.assertIn(f"ROLLBACK_PARTIAL old_image={old_image}", result.stderr)
        self.assertNotIn(f"ROLLBACK_DONE old_image={old_image}", result.stdout)
        self.assertEqual(before, after)
        self.assertEqual(leftovers, [])

    def test_sigterm_during_health_wait_rolls_back_old_image_and_config(self):
        old_image = "sha256:old-image-sigterm"
        stored = {"port": 28080, "panel_path": "/admin", "username": "admin"}
        result, calls, before, after, leftovers = self.deploy(
            stored=stored, override="30080", probe_code="503", old_image=old_image,
            signal_at_sleep=True, conf_mode=0o600,
        )
        self.assertEqual(result.returncode, 143, result.stderr)
        self.assertEqual(before, after)
        self.assertEqual(json.loads(after), stored)
        self.assertIn(f"ROLLBACK_DONE old_image={old_image}", result.stdout)
        self.assertNotIn("更新完成", result.stdout)
        self.assertEqual(leftovers, [])
        docker_calls = [call for call in calls if call[0] == "docker"]
        self.assertEqual(docker_calls[-1][-1], old_image)

    def test_successful_deployment_leaves_no_backup_files(self):
        stored = {"port": 28080, "panel_path": "/admin", "username": "admin"}
        old_image = "sha256:old-img-999"
        result, calls, before, after, leftovers = self.deploy(
            stored=stored,
            override="30080",
            probe_code="200",
            old_image=old_image,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("更新完成", result.stdout)
        self.assertEqual(json.loads(after), {**stored, "port": 30080})
        self.assertEqual(leftovers, [], "Successful deployment must not leave backup files")


if __name__ == "__main__":
    unittest.main()
