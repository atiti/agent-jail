import os
import subprocess
import unittest


ROOT = os.path.dirname(os.path.dirname(__file__))


class ManualSuiteTests(unittest.TestCase):
    def test_manual_policy_suite_lists_cases(self):
        proc = subprocess.run(
            ["bash", "scripts/manual_policy_suite.sh", "--list"],
            cwd=ROOT,
            text=True,
            capture_output=True,
        )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("allow_repo_cat", proc.stdout)
        self.assertIn("deny_system_cat", proc.stdout)
        self.assertIn("observe_dmesg", proc.stdout)
