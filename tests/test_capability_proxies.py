import os
import unittest
from unittest import mock

from agent_jail.browser_proxy import run_browser_proxy
from agent_jail.delegate_proxy import prepare_delegate_proxy, run_delegate_proxy
from agent_jail.skills_proxy import run_skill_proxy


class CapabilityProxyTests(unittest.TestCase):
    def test_delegate_requires_capability_allow(self):
        with self.assertRaises(PermissionError):
            run_delegate_proxy({"delegates": []}, {}, "ops", ["opsctl", "status"])

    def test_delegate_builds_run_as_command(self):
        result = run_delegate_proxy(
            {"delegates": ["ops"]},
            {"ops": {"name": "ops", "run_as_user": "delegate-runner", "executor": "/usr/local/bin/delegate-exec", "allowed_tools": ["opsctl"]}},
            "ops",
            ["opsctl", "status", "."],
        )
        self.assertEqual(result["delegated_command"][:5], ["sudo", "-n", "-u", "delegate-runner", "/usr/local/bin/delegate-exec"])

    def test_prepare_delegate_proxy_rejects_disallowed_tool(self):
        with self.assertRaises(PermissionError):
            prepare_delegate_proxy(
                {"delegates": ["ops"]},
                {"ops": {"name": "ops", "executor": "/usr/local/bin/delegate-exec", "allowed_tools": ["opsctl"]}},
                "ops",
                ["python3", "-c", "print('nope')"],
            )

    def test_prepare_delegate_proxy_rejects_script_entrypoint_for_inventory_delegate(self):
        with self.assertRaises(PermissionError) as exc:
            prepare_delegate_proxy(
                {"delegates": ["ops"]},
                {
                    "ops": {
                        "name": "ops",
                        "executor": "/usr/local/bin/delegate-exec",
                        "strip_tool_name": True,
                        "auto_inventory_from_cwd": True,
                        "inventory_tools": ["opsctl"],
                        "_cwd": "/repo",
                    }
                },
                "ops",
                ["./scripts/service-health.sh", "summary"],
            )
        self.assertIn("expects a control-plane tool entrypoint", str(exc.exception))

    def test_delegate_can_strip_tool_name_for_tool_wrapper_executor(self):
        result = run_delegate_proxy(
            {"delegates": ["ops"]},
            {
                "ops": {
                    "name": "ops",
                    "run_as_user": "delegate-runner",
                    "executor": "/usr/local/bin/delegate-exec",
                    "allowed_tools": ["opsctl"],
                    "strip_tool_name": True,
                }
            },
            "ops",
            ["opsctl", "status", "."],
        )
        self.assertEqual(
            result["delegated_command"],
            ["sudo", "-n", "-u", "delegate-runner", "/usr/local/bin/delegate-exec", "status", "."],
        )

    def test_delegate_execute_returns_subprocess_output(self):
        with mock.patch("agent_jail.delegate_proxy.subprocess.run") as mocked_run:
            mocked_run.return_value = mock.Mock(returncode=0, stdout="ok\n", stderr="")
            with mock.patch.dict(os.environ, {"AGENT_JAIL_HOST_HOME": "/Users/example", "AGENT_JAIL_ORIG_PATH": "/usr/bin:/bin"}, clear=False):
                result = run_delegate_proxy(
                    {"delegates": ["ops"]},
                    {
                        "ops": {
                            "name": "ops",
                            "executor": "/usr/local/bin/delegate-exec",
                            "allowed_tools": ["opsctl"],
                            "strip_tool_name": True,
                            "mode": "execute",
                        }
                    },
                    "ops",
                    ["opsctl", "status"],
                )
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["stdout"], "ok\n")
        mocked_run.assert_called_once()
        self.assertEqual(mocked_run.call_args.kwargs["env"]["HOME"], "/Users/example")
        self.assertEqual(mocked_run.call_args.kwargs["env"]["PATH"], "/usr/bin:/bin")

    def test_delegate_execute_adds_inventory_tool_dry_run_note_without_approve(self):
        with mock.patch("agent_jail.delegate_proxy.subprocess.run") as mocked_run:
            mocked_run.return_value = mock.Mock(returncode=0, stdout="ok\n", stderr="")
            result = run_delegate_proxy(
                {"delegates": ["ops"]},
                {
                    "ops": {
                        "name": "ops",
                        "executor": "/usr/local/bin/delegate-exec",
                        "allowed_tools": ["opsctl"],
                        "strip_tool_name": True,
                        "mode": "execute",
                    }
                },
                "ops",
                ["opsctl", "exec", "--service", "svc", "--cmd", "uptime"],
            )
        self.assertIn("defaults to dry-run", result["note"])

    def test_delegate_execute_applies_configured_env(self):
        with mock.patch("agent_jail.delegate_proxy.subprocess.run") as mocked_run:
            mocked_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch.dict(os.environ, {"AGENT_JAIL_HOST_HOME": "/Users/example"}, clear=False):
                run_delegate_proxy(
                    {"delegates": ["ops"]},
                    {
                        "ops": {
                            "name": "ops",
                            "executor": "/usr/local/bin/delegate-exec",
                            "allowed_tools": ["./scripts/secret-tool.sh"],
                            "mode": "execute",
                            "set_env": {"SECRET_KEY_FILE": "~/keys.txt"},
                        }
                    },
                    "ops",
                    ["./scripts/secret-tool.sh", "status"],
                )
        self.assertEqual(mocked_run.call_args.kwargs["env"]["SECRET_KEY_FILE"], "/Users/example/keys.txt")

    def test_delegate_execute_injects_only_required_secret_env(self):
        with mock.patch("agent_jail.delegate_proxy.subprocess.run") as mocked_run:
            mocked_run.return_value = mock.Mock(returncode=0, stdout="", stderr="")
            with mock.patch.dict(os.environ, {"AGENT_JAIL_HOST_HOME": "/Users/example"}, clear=False):
                run_delegate_proxy(
                    {"delegates": ["ops"]},
                    {
                        "ops": {
                            "name": "ops",
                            "executor": "/usr/local/bin/delegate-exec",
                            "allowed_tools": ["python3"],
                            "allowed_secrets": ["age_key_file"],
                            "configured_secrets": {
                                "age_key_file": {"env": {"AGE_KEY_FILE": "~/keys.txt"}},
                                "other_secret": {"env": {"OTHER_SECRET": "~/other.txt"}},
                            },
                            "mode": "execute",
                        }
                    },
                    "ops",
                    ["python3", "-c", "import os; print(os.environ['AGE_KEY_FILE'])"],
                )
        env = mocked_run.call_args.kwargs["env"]
        self.assertEqual(env["AGE_KEY_FILE"], "/Users/example/keys.txt")
        self.assertNotIn("OTHER_SECRET", env)

    def test_delegate_auto_inventory_defaults_from_cwd(self):
        with mock.patch("agent_jail.delegate_proxy.os.path.isdir", return_value=True):
            result = run_delegate_proxy(
                {"delegates": ["ops"]},
                {
                    "ops": {
                        "name": "ops",
                        "executor": "/usr/local/bin/delegate-exec",
                        "allowed_tools": ["opsctl"],
                        "inventory_tools": ["opsctl"],
                        "strip_tool_name": True,
                        "auto_inventory_from_cwd": True,
                        "_cwd": "/repo",
                    }
                },
                "ops",
                ["opsctl", "status", "--service", "svc"],
            )
        self.assertEqual(
            result["delegated_command"],
            [
                "/usr/local/bin/delegate-exec",
                "--ops-root",
                "/repo",
                "--inventory-dir",
                "/repo/inventory",
                "status",
                "--service",
                "svc",
            ],
        )

    def test_browser_automation_routes_to_host_proxy(self):
        result = run_browser_proxy({"browser_automation": True}, {"tool": "peekaboo", "action": "screenshot"})
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["tool"], "peekaboo")

    def test_skill_proxy_requires_proxy_capability(self):
        with self.assertRaises(PermissionError):
            run_skill_proxy({"skills_proxy": False}, {"name": "gmail", "operation": "search"})
