import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
CLI = os.path.join(ROOT, "agent-jail")


class CLITests(unittest.TestCase):
    def run_cli(self, *args, env=None):
        proc = subprocess.run(
            [CLI, *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=env,
        )
        return proc

    def test_run_requires_target(self):
        proc = self.run_cli("run")
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("usage", proc.stderr.lower())

    def test_run_invokes_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli("run", sys.executable, "-c", "print('ok')", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "ok")

    def test_run_returns_127_for_missing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli("run", "definitely-not-a-real-command-12345", env=env)
        self.assertEqual(proc.returncode, 127)
        self.assertIn("target command not found", proc.stderr.lower())

    def test_mounts_codex_and_claude_home_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".claude"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(jail_home)
                codex_link = os.path.islink(os.path.join(jail_home, ".codex"))
                claude_link = os.path.islink(os.path.join(jail_home, ".claude"))
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            self.assertEqual({m["source"] for m in mounts}, {os.path.join(real_home, ".codex"), os.path.join(real_home, ".claude")})
            self.assertTrue(codex_link)
            self.assertTrue(claude_link)

    def test_can_disable_codex_and_claude_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".claude"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(jail_home, mount_codex_home=False, mount_claude_home=False)
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
        self.assertEqual(mounts, [])

    def test_existing_target_is_backed_up_and_replaced(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(jail_home, ".codex"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(jail_home, mount_claude_home=False)
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            backup_entries = [entry for entry in mounts if entry.get("status") == "backed-up-existing-target"]
            self.assertEqual(len(backup_entries), 1)
            self.assertTrue(os.path.exists(backup_entries[0]["backup"]))
            self.assertTrue(os.path.islink(os.path.join(jail_home, ".codex")))

    def test_run_aborts_when_kill_switch_exists_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            kill_switch = os.path.join(tmp, "stop")
            open(kill_switch, "w", encoding="utf-8").close()
            proc = self.run_cli("run", "--kill-switch", kill_switch, sys.executable, "-c", "print('nope')", env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("kill switch", proc.stderr.lower())

    def test_run_stops_process_when_kill_switch_appears(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            kill_switch = os.path.join(tmp, "stop")

            def trigger():
                time.sleep(0.3)
                open(kill_switch, "w", encoding="utf-8").close()

            thread = threading.Thread(target=trigger, daemon=True)
            thread.start()
            proc = self.run_cli(
                "run",
                "--kill-switch",
                kill_switch,
                sys.executable,
                "-c",
                "import time; time.sleep(5)",
                env=env,
            )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("kill switch", proc.stderr.lower())
