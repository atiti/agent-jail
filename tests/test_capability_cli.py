import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

from agent_jail.broker import BrokerServer
from agent_jail.policy import PolicyStore


ROOT = os.path.dirname(os.path.dirname(__file__))
CAP_CLI = os.path.join(ROOT, "agent-jail-cap")


class CapabilityCLITests(unittest.TestCase):
    def run_cap(self, *args, env=None):
        return subprocess.run(
            [sys.executable, CAP_CLI, *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=env,
        )

    def test_ops_capability_round_trip(self):
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = os.path.join(tmp, "broker.sock")
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            server = BrokerServer(sock_path, store, capabilities={"ops_exec": True})
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.close)
            env = os.environ.copy()
            env["AGENT_JAIL_SOCKET"] = sock_path
            proc = self.run_cap("ops", "marksterctl", "status", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        payload = json.loads(proc.stdout)
        self.assertEqual(payload["status"], "ok")
        self.assertEqual(payload["command"], ["marksterctl", "status"])

    def test_browser_capability_denied_without_allow(self):
        with tempfile.TemporaryDirectory() as tmp:
            sock_path = os.path.join(tmp, "broker.sock")
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            server = BrokerServer(sock_path, store, capabilities={"browser_automation": False})
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(server.close)
            env = os.environ.copy()
            env["AGENT_JAIL_SOCKET"] = sock_path
            proc = self.run_cap("browser", "peekaboo", "screenshot", env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("denied", proc.stderr.lower())
