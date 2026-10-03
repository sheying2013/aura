"""Offline packaging checks: execute isolated shell functions, never the installer."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = (ROOT / "install.sh").read_text()


def shell_function(name):
    match = re.search(rf"^{name}\(\) \{{\n.*?^\}}$", INSTALLER, re.M | re.S)
    if not match:
        raise AssertionError(f"Installer function {name} is missing")
    return match.group()


def shell_env(**updates):
    env = os.environ.copy()
    for key in list(env):
        if key.startswith("AURA_"):
            del env[key]
    env.update(updates)
    return env


def run_shell(source, *, env, input_text=""):
    return subprocess.run(
        ["bash", "-euo", "pipefail", "-c", source],
        env=env, input=input_text, capture_output=True, text=True, timeout=10,
    )


class InstallerRegressionTests(unittest.TestCase):
    def configure(self, *, explicit=None, existing=False, interactive=False):
        with tempfile.TemporaryDirectory(prefix="aura packaging ") as tmp:
            root = Path(tmp)
            backend = root / "backend"
            backend.mkdir()
            state = backend / "state.json"
            state.write_text(json.dumps({"auth": {"password_hash": "existing"}} if existing else {}))
            # These local modules record what the real installer Python block writes.
            (backend / "db.py").write_text(
                "import json\nfrom pathlib import Path\n"
                "STATE = Path('state.json')\n"
                "def init_db(): pass\n"
                "def get_setting(key, default): return json.loads(STATE.read_text()).get(key, default)\n"
                "def set_setting(key, value):\n"
                "    data = json.loads(STATE.read_text())\n"
                "    data[key] = value\n"
                "    STATE.write_text(json.dumps(data))\n"
            )
            (backend / "panel_config.py").write_text(
                "import json\nfrom pathlib import Path\n"
                "def set_many(value): Path('panel.json').write_text(json.dumps(value))\n"
            )
            (backend / "auth.py").write_text("def hash_password(value): return 'hashed:' + value\n")
            env = shell_env(SRC_DIR=str(root), PY=sys.executable)
            if explicit is not None:
                env["AURA_PASSWORD"] = explicit
            source = "\n".join([
                'info() { :; }; ok() { :; }; fail() { printf "%s" "$1" >&2; exit 1; }',
                'PORT=""; PATH_PREFIX=""; USERNAME=""; PASSWORD="${AURA_PASSWORD:-}"',
                f'SKIP_INPUT="{0 if interactive else 1}"',
                shell_function("prompt_input"), shell_function("configure_panel"),
                "configure_panel",
            ])
            result = run_shell(source, env=env, input_text="\n\n\n\n" if interactive else "")
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(state.read_text()), json.loads((backend / "panel.json").read_text())

    def test_unset_password_generates_candidate_and_keeps_existing_password(self):
        state, panel = self.configure(existing=True)
        self.assertEqual(state["auth"]["password_hash"], "existing")
        self.assertEqual(panel, {"port": 19001, "panel_path": "/admin", "username": "admin"})

    def test_first_install_without_password_sets_generated_password(self):
        state, _ = self.configure()
        self.assertTrue(state["auth"]["password_hash"].startswith("hashed:"))
        self.assertGreaterEqual(len(state["auth"]["password_hash"].removeprefix("hashed:")), 6)

    def test_explicit_password_overrides_existing_and_preserves_special_characters(self):
        password = "quoted'$password `literal`\\ with space"
        state, _ = self.configure(explicit=password, existing=True)
        self.assertEqual(state["auth"]["password_hash"], "hashed:" + password)

    def test_interactive_defaults_are_values_without_prompt_text(self):
        state, panel = self.configure(existing=True, interactive=True)
        self.assertEqual(panel["port"], 19001)
        self.assertEqual(panel["panel_path"], "/admin")
        self.assertEqual(panel["username"], "admin")
        self.assertEqual(state["auth"]["password_hash"], "existing")

    def test_sync_frontend_copies_canonical_html_and_js(self):
        with tempfile.TemporaryDirectory(prefix="aura packaging ") as tmp:
            root = Path(tmp)
            (root / "backend").mkdir()
            (root / "static/js").mkdir(parents=True)
            (root / "index.html").write_text("canonical html")
            (root / "static/js/main.js").write_text("canonical js")
            result = run_shell(
                'ok() { :; };\n' + shell_function("sync_frontend") + "\nsync_frontend",
                env=shell_env(SRC_DIR=str(root)),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual((root / "backend/static/index.html").read_text(), "canonical html")
            self.assertEqual((root / "backend/static/js/main.js").read_text(), "canonical js")

    def test_macos_unset_skip_input_reaches_foreground_after_declining_launchd(self):
        with tempfile.TemporaryDirectory(prefix="aura packaging ") as tmp:
            root = Path(tmp)
            (root / "backend").mkdir()
            (root / "bin").mkdir()
            fake_bash = root / "bin/bash"
            fake_bash.write_text('#!/bin/sh\nprintf "%s\\n" "$*"\n')
            fake_bash.chmod(0o755)
            env = shell_env(SRC_DIR=str(root), PORT="19001", PATH_PREFIX="/admin")
            env["PATH"] = str(root / "bin") + os.pathsep + env["PATH"]
            source = 'warn() { :; }; launchctl() { exit 99; };\n' + shell_function("start_mac") + "\nstart_mac"
            # Use the real Bash executable before injecting the stub into PATH.
            result = subprocess.run(
                [shutil.which("bash"), "-euo", "pipefail", "-c", source],
                env=env, input="\n", capture_output=True, text=True, timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("start.sh", result.stdout)


class PackagingRegressionTests(unittest.TestCase):
    def run_start(self, root, *, port="23456", python_fails=False):
        backend = root / "backend"
        backend.mkdir(exist_ok=True)
        shutil.copyfile(ROOT / "backend/start.sh", backend / "start.sh")
        bin_dir = root / "bin"
        bin_dir.mkdir()
        for name, body in {
            "python3": "exit 1" if python_fails else f"printf '%s\\n' '{port}'",
            "uvicorn": 'printf "%s\\n" "$@"',
        }.items():
            path = bin_dir / name
            path.write_text("#!/bin/sh\n" + body + "\n")
            path.chmod(0o755)
        env = shell_env()
        env["PATH"] = str(bin_dir) + os.pathsep + env["PATH"]
        result = subprocess.run(
            ["bash", str(backend / "start.sh")], env=env,
            capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["app:app", "--host", "0.0.0.0", "--port", port])

    def test_start_overwrites_stale_frontend_from_repository_root(self):
        with tempfile.TemporaryDirectory(prefix="aura packaging ") as tmp:
            root = Path(tmp)
            (root / "static/js").mkdir(parents=True)
            (root / "backend/static/js").mkdir(parents=True)
            (root / "index.html").write_text("canonical html")
            (root / "static/js/main.js").write_text("canonical js")
            (root / "backend/static/index.html").write_text("stale html")
            (root / "backend/static/js/main.js").write_text("stale js")
            self.run_start(root)
            self.assertEqual((root / "backend/static/index.html").read_text(), "canonical html")
            self.assertEqual((root / "backend/static/js/main.js").read_text(), "canonical js")

    def test_docker_frontend_copy_paths_and_start_without_root_sources(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        with tempfile.TemporaryDirectory(prefix="aura packaging ") as tmp:
            root = Path(tmp)
            # Emulate only frontend COPY operations; no Docker execution or downloads.
            for source, target in re.findall(r"^COPY (index\.html|static/js/) (\S+)$", dockerfile, re.M):
                destination = root / target.removeprefix("/app/")
                destination.mkdir(parents=True, exist_ok=True)
                if source.endswith("/"):
                    shutil.copytree(ROOT / source, destination, dirs_exist_ok=True)
                else:
                    shutil.copyfile(ROOT / source, destination / source)
            html = root / "backend/static/index.html"
            self.assertTrue(html.is_file(), "Docker must package canonical index.html")
            scripts = re.findall(r'<script\s+src="([^"?]+)', html.read_text())
            self.assertIn("js/main.js", scripts)
            for script in scripts:
                self.assertTrue((html.parent / script).is_file(), f"Docker is missing {script}")
            self.assertFalse((root / "index.html").exists())
            self.assertFalse((root / "static/js").exists())
            self.run_start(root)

    def test_start_falls_back_to_default_port_when_config_read_fails(self):
        with tempfile.TemporaryDirectory(prefix="aura packaging ") as tmp:
            self.run_start(Path(tmp), port="19001", python_fails=True)

    def test_removed_subscription_module_has_no_packaging_or_page_references(self):
        self.assertFalse((ROOT / "subs.js").exists())
        self.assertFalse((ROOT / "backend/static/subs.js").exists())
        for path in ("Dockerfile", "install.sh", "backend/start.sh", "README.md", "index.html", "backend/static/index.html"):
            text = (ROOT / path).read_text()
            self.assertNotIn("subs.js", text, path)
            self.assertNotIn("SubscriptionManager", text, path)

    def test_dockerignore_keeps_backups_and_local_test_assets_out_of_context(self):
        patterns = (ROOT / ".dockerignore").read_text().splitlines()
        for pattern in ("*.bak*", "**/*.bak*", "/tests/", "/test-*.json", "/*.py"):
            self.assertIn(pattern, patterns)


if __name__ == "__main__":
    unittest.main()
