import unittest

from agent_jail.browser_proxy import run_browser_proxy
from agent_jail.ops_proxy import run_ops_proxy
from agent_jail.skills_proxy import run_skill_proxy


class CapabilityProxyTests(unittest.TestCase):
    def test_ops_exec_requires_capability_allow(self):
        with self.assertRaises(PermissionError):
            run_ops_proxy({"ops_exec": False}, ["marksterctl", "status"])

    def test_browser_automation_routes_to_host_proxy(self):
        result = run_browser_proxy({"browser_automation": True}, {"tool": "peekaboo", "action": "screenshot"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["tool"], "peekaboo")

    def test_skill_proxy_requires_proxy_capability(self):
        with self.assertRaises(PermissionError):
            run_skill_proxy({"skills_proxy": False}, {"name": "gmail", "operation": "search"})
