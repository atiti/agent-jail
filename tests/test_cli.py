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
