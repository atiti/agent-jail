import os
import subprocess
import sys
import tempfile
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))
CLI = os.path.join(ROOT, "agent-jail")


class CLITests(unittest.TestCase):
    def run_cli(self, *args, env=None):
        proc = subprocess.run(
            [sys.executable, CLI, *args],
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
