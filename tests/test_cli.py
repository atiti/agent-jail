import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import unittest
from unittest import mock

from agent_jail.main import (
    _format_review_list,
    _format_suggestion_report,
    _review_suggestions_interactively,
    default_secret_deny_patterns,
    discover_launch_read_paths,
    render_cap_launcher,
)
from agent_jail.policy import PolicyStore

ROOT = os.path.dirname(os.path.dirname(__file__))
CLI = os.path.join(ROOT, "agent-jail")


class CLITests(unittest.TestCase):
    def assertProxyUrl(self, url, scheme):
        self.assertIsNotNone(url)
        parsed = urllib.parse.urlsplit(url)
        self.assertEqual(parsed.scheme, scheme)
        self.assertEqual(parsed.hostname, "127.0.0.1")
        self.assertEqual(parsed.username, "agent-jail")
        self.assertTrue(parsed.password)
        self.assertIsNotNone(parsed.port)

    def run_cli(self, *args, env=None):
        merged_env = os.environ.copy()
        merged_env["AGENT_JAIL_BACKEND"] = "host"
        if env:
            merged_env.update(env)
        proc = subprocess.run(
            [CLI, *args],
            cwd=ROOT,
            text=True,
            capture_output=True,
            env=merged_env,
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

    def test_run_uses_session_home_separate_from_state_home(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HOME','AGENT_JAIL_HOME','AGENT_JAIL_STATE_HOME')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertEqual(values["HOME"], values["AGENT_JAIL_HOME"])
        self.assertEqual(values["AGENT_JAIL_STATE_HOME"], tmp)
        self.assertNotEqual(values["AGENT_JAIL_HOME"], tmp)

    def test_run_strips_host_secrets_from_child_env_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env.update(
                {
                    "AGENT_JAIL_HOME": tmp,
                    "OPENAI_API_KEY": "host-openai-secret",
                    "AZURE_OPENAI_API_KEY": "host-azure-secret",
                    "KEEP_ME": "host-value",
                    "SSH_AUTH_SOCK": "/tmp/test-ssh.sock",
                }
            )
            proc = self.run_cli(
                "run",
                sys.executable,
                "-c",
                (
                    "import json, os; "
                    "print(json.dumps({k: os.environ.get(k) for k in "
                    "('OPENAI_API_KEY','AZURE_OPENAI_API_KEY','KEEP_ME','SSH_AUTH_SOCK','AGENT_JAIL_SOURCE_ROOT','AGENT_JAIL_SOCKET')}, sort_keys=True))"
                ),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertIsNone(values["OPENAI_API_KEY"])
        self.assertIsNone(values["AZURE_OPENAI_API_KEY"])
        self.assertIsNone(values["KEEP_ME"])
        self.assertEqual(values["SSH_AUTH_SOCK"], "/tmp/test-ssh.sock")
        self.assertIsNone(values["AGENT_JAIL_SOURCE_ROOT"])
        self.assertTrue(values["AGENT_JAIL_SOCKET"])

    def test_run_preserves_configured_env_names_and_prefixes(self):
        with tempfile.TemporaryDirectory() as tmp:
            with open(os.path.join(tmp, "config.json"), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "defaults": {
                            "run": {
                                "preserve_env": ["KEEP_ME"],
                                "preserve_env_prefixes": ["MYAPP_"],
                            }
                        }
                    },
                    handle,
                )
            env = os.environ.copy()
            env.update(
                {
                    "AGENT_JAIL_HOME": tmp,
                    "KEEP_ME": "keep",
                    "MYAPP_TOKEN": "prefix-keep",
                    "DROP_ME": "drop",
                }
            )
            proc = self.run_cli(
                "run",
                sys.executable,
                "-c",
                (
                    "import json, os; "
                    "print(json.dumps({k: os.environ.get(k) for k in ('KEEP_ME','MYAPP_TOKEN','DROP_ME')}, sort_keys=True))"
                ),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertEqual(values["KEEP_ME"], "keep")
        self.assertEqual(values["MYAPP_TOKEN"], "prefix-keep")
        self.assertIsNone(values["DROP_ME"])

    def test_run_returns_127_for_missing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli("run", "definitely-not-a-real-command-12345", env=env)
        self.assertEqual(proc.returncode, 127)
        self.assertIn("target command not found", proc.stderr.lower())

    def test_resolve_target_prefers_host_path_for_top_level_codex(self):
        with tempfile.TemporaryDirectory() as tmp:
            wrapper_dir = os.path.join(tmp, ".agent-jail", "bin")
            host_dir = os.path.join(tmp, "host-bin")
            os.makedirs(wrapper_dir)
            os.makedirs(host_dir)
            wrapper_target = os.path.join(wrapper_dir, "codex")
            host_target = os.path.join(host_dir, "codex")
            with open(wrapper_target, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            with open(host_target, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(wrapper_target, 0o755)
            os.chmod(host_target, 0o755)
            from agent_jail.main import resolve_target

            resolved = resolve_target(
                ["codex", "resume", "session-id"],
                {
                    "PATH": wrapper_dir,
                    "AGENT_JAIL_ORIG_PATH": host_dir,
                },
            )
        self.assertEqual(resolved[0], os.path.realpath(host_target))
        self.assertEqual(resolved[1:], ["resume", "session-id"])

    def test_resolve_target_rewrites_codex_js_shim_to_host_node(self):
        with tempfile.TemporaryDirectory() as tmp:
            host_dir = os.path.join(tmp, "host-bin")
            os.makedirs(host_dir)
            script_target = os.path.join(host_dir, "codex.js")
            codex_target = os.path.join(host_dir, "codex")
            node_target = os.path.join(host_dir, "node")
            with open(script_target, "w", encoding="utf-8") as handle:
                handle.write("#!/usr/bin/env node\nconsole.log('codex')\n")
            with open(node_target, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            os.chmod(script_target, 0o755)
            os.chmod(node_target, 0o755)
            os.symlink("codex.js", codex_target)
            from agent_jail.main import resolve_target

            resolved = resolve_target(
                ["codex", "resume", "session-id"],
                {
                    "PATH": host_dir,
                    "AGENT_JAIL_ORIG_PATH": host_dir,
                },
            )
        self.assertEqual(resolved[0], os.path.realpath(node_target))
        self.assertEqual(resolved[1], os.path.realpath(script_target))
        self.assertEqual(resolved[2:], ["resume", "session-id"])

    def test_run_uses_default_project_and_filesystem_roots_from_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            home = os.path.join(tmp, "home")
            build_root = os.path.join(tmp, "build")
            workspace_root = os.path.join(tmp, "workspace")
            os.makedirs(repo)
            os.makedirs(home)
            os.makedirs(build_root)
            os.makedirs(workspace_root)
            with open(os.path.join(home, "config.json"), "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "defaults": {
                            "run": {
                                "read_only_roots": [build_root],
                                "write_roots": [workspace_root],
                                "allow_ops": True,
                                "allow_delegates": ["local-secrets"],
                                "project_mode": "cwd",
                            }
                        }
                    },
                    handle,
                )
            proc = subprocess.run(
                [
                    CLI,
                    "run",
                    sys.executable,
                    "-c",
                    "import json, os; print(json.dumps(json.loads(os.environ['AGENT_JAIL_MOUNTS']), sort_keys=True)); print(os.environ['AGENT_JAIL_CAPABILITIES'])",
                ],
                cwd=repo,
                text=True,
                capture_output=True,
                env={**os.environ, "AGENT_JAIL_BACKEND": "host", "AGENT_JAIL_HOME": home},
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        mounts_json, capabilities_json = proc.stdout.strip().splitlines()
        mounts = [
            {"path": os.path.realpath(item["path"]), "mode": item["mode"]}
            for item in json.loads(mounts_json)
        ]
        capabilities = json.loads(capabilities_json)
        self.assertIn({"path": os.path.realpath(repo), "mode": "rw"}, mounts)
        self.assertIn({"path": os.path.realpath(build_root), "mode": "ro"}, mounts)
        self.assertIn({"path": os.path.realpath(workspace_root), "mode": "rw"}, mounts)
        self.assertTrue(capabilities["ops_exec"])
        self.assertIn("local-secrets", capabilities["delegates"])

    def test_default_secret_deny_patterns_include_root_and_nested_secret_files(self):
        patterns = default_secret_deny_patterns(["/Users/example/project"])

        self.assertIn("/Users/example/project/.env", patterns)
        self.assertIn("/Users/example/project/.npmrc", patterns)
        self.assertIn("/Users/example/project/**/.env.*", patterns)
        self.assertIn("/Users/example/project/**/id_rsa", patterns)
        self.assertIn("/Users/example/project/**/secrets/**", patterns)

    def test_discover_launch_read_paths_includes_node_package_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            package_root = os.path.join(tmp, "lib", "node_modules", "@openai", "codex")
            bin_dir = os.path.join(tmp, "bin")
            os.makedirs(os.path.join(package_root, "bin"), exist_ok=True)
            os.makedirs(bin_dir, exist_ok=True)
            script_path = os.path.join(package_root, "bin", "codex.js")
            node_path = os.path.join(bin_dir, "node")
            package_json = os.path.join(package_root, "package.json")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write("console.log('ok')\n")
            with open(node_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nexit 0\n")
            with open(package_json, "w", encoding="utf-8") as handle:
                handle.write("{}\n")

            paths = discover_launch_read_paths([node_path, script_path])

        self.assertIn(os.path.realpath(node_path), paths)
        self.assertIn(os.path.realpath(script_path), paths)
        self.assertIn(os.path.realpath(package_root), paths)

    def test_run_includes_local_skill_roots_as_read_only_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            home = os.path.join(tmp, "home")
            real_home = os.path.join(tmp, "real-home")
            os.makedirs(repo)
            os.makedirs(home)
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".agents"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                proc = subprocess.run(
                    [
                        CLI,
                        "run",
                        sys.executable,
                        "-c",
                        "import json, os; print(json.dumps(json.loads(os.environ['AGENT_JAIL_MOUNTS']), sort_keys=True))",
                    ],
                    cwd=repo,
                    text=True,
                    capture_output=True,
                    env={**os.environ, "AGENT_JAIL_BACKEND": "host", "AGENT_JAIL_HOME": home},
                )
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
        self.assertEqual(proc.returncode, 0, proc.stderr)
        mounts = {os.path.realpath(item["path"]): item["mode"] for item in json.loads(proc.stdout.strip())}
        self.assertEqual(mounts[os.path.realpath(os.path.join(real_home, ".codex"))], "ro")
        self.assertEqual(mounts[os.path.realpath(os.path.join(real_home, ".agents"))], "ro")

    def test_config_show_prints_current_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            config_path = os.path.join(tmp, "config.json")
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump({"defaults": {"run": {"allow_ops": True}}}, handle)
            proc = self.run_cli("config", "show", env={"AGENT_JAIL_HOME": tmp})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        data = json.loads(proc.stdout)
        self.assertTrue(data["defaults"]["run"]["allow_ops"])

    def test_config_set_defaults_updates_run_profile(self):
        with tempfile.TemporaryDirectory() as tmp:
            proc = self.run_cli(
                "config",
                "set-defaults",
                "--read-only-root",
                "~/build",
                "--write-root",
                "~/workspace",
                "--home-mount",
                ".config/opencode",
                "--git-ssh-host",
                "github.com",
                "--preserve-env",
                "KEEP_ME",
                "--preserve-env-prefix",
                "MYAPP_",
                "--proxy",
                "--allow-ops",
                "--allow-delegate",
                "local-secrets",
                "--project-mode",
                "cwd",
                env={"AGENT_JAIL_HOME": tmp},
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            with open(os.path.join(tmp, "config.json"), encoding="utf-8") as handle:
                config = json.load(handle)
        self.assertEqual(
            config["defaults"]["run"]["read_only_roots"],
            [os.path.abspath(os.path.expanduser("~/build"))],
        )
        self.assertEqual(
            config["defaults"]["run"]["write_roots"],
            [os.path.abspath(os.path.expanduser("~/workspace"))],
        )
        self.assertEqual(config["defaults"]["run"]["home_mounts"], [".config/opencode", ".overwatchr"])
        self.assertEqual(config["defaults"]["run"]["git_ssh_hosts"], ["github.com"])
        self.assertEqual(config["defaults"]["run"]["preserve_env"], ["KEEP_ME"])
        self.assertEqual(config["defaults"]["run"]["preserve_env_prefixes"], ["MYAPP_"])
        self.assertTrue(config["defaults"]["run"]["proxy"])
        self.assertTrue(config["defaults"]["run"]["allow_ops"])
        self.assertEqual(config["defaults"]["run"]["allow_delegates"], ["local-secrets"])
        self.assertEqual(config["defaults"]["run"]["project_mode"], "cwd")

    def test_network_allow_list_test_and_deny_manage_policy_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = {"AGENT_JAIL_HOME": tmp}
            allow = self.run_cli("network", "allow", "example.com", "--port", "443", "--scheme", "tcp", env=env)
            self.assertEqual(allow.returncode, 0, allow.stderr)
            listed = self.run_cli("network", "list", env=env)
            self.assertEqual(listed.returncode, 0, listed.stderr)
            self.assertIn("example.com", listed.stdout)
            self.assertIn("443", listed.stdout)
            self.assertIn("tcp", listed.stdout)
            tested = self.run_cli("network", "test", "example.com", "--port", "443", "--scheme", "tcp", env=env)
            self.assertEqual(tested.returncode, 0, tested.stderr)
            self.assertIn("allow", tested.stdout)
            deny = self.run_cli("network", "deny", "example.com", "--port", "443", "--scheme", "tcp", env=env)
            self.assertEqual(deny.returncode, 0, deny.stderr)
            tested_again = self.run_cli("network", "test", "example.com", "--port", "443", "--scheme", "tcp", env=env)
            self.assertEqual(tested_again.returncode, 0, tested_again.stderr)
            self.assertIn("deny", tested_again.stdout)

    def test_run_with_proxy_sets_hybrid_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertProxyUrl(values["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["HTTPS_PROXY"], "http")
        self.assertIsNone(values["ALL_PROXY"])
        self.assertProxyUrl(values["SOCKS_PROXY"], "socks5")

    def test_run_defaults_to_proxy_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertProxyUrl(values["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["HTTPS_PROXY"], "http")
        self.assertIsNone(values["ALL_PROXY"])
        self.assertProxyUrl(values["SOCKS_PROXY"], "socks5")

    def test_run_can_disable_default_proxy(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--no-proxy",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            json.loads(proc.stdout.strip()),
            {"ALL_PROXY": None, "HTTPS_PROXY": None, "HTTP_PROXY": None, "SOCKS_PROXY": None},
        )

    def test_run_with_proxy_commands_only_keeps_parent_clean_and_proxies_wrapped_child(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-commands-only",
                "python3",
                "-c",
                (
                    "import json, os, subprocess; "
                    "parent={k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}; "
                    "child=json.loads(subprocess.check_output(['bash','-lc',"
                    "\"python3 -c \\\"import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))\\\"\""
                    "], text=True)); "
                    "print(json.dumps({'parent': parent, 'child': child}, sort_keys=True))"
                ),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertEqual(values["parent"], {"ALL_PROXY": None, "HTTPS_PROXY": None, "HTTP_PROXY": None, "SOCKS_PROXY": None})
        self.assertProxyUrl(values["child"]["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["child"]["HTTPS_PROXY"], "http")
        self.assertIsNone(values["child"]["ALL_PROXY"])
        self.assertProxyUrl(values["child"]["SOCKS_PROXY"], "socks5")

    def test_run_with_proxy_commands_only_keeps_codex_bootstrap_clean(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            env["http_proxy"] = "http://host-proxy.invalid:8080"
            env["https_proxy"] = "http://host-proxy.invalid:8080"
            env["REQUESTS_CA_BUNDLE"] = "/tmp/host-ca.pem"
            fake_bin = os.path.join(tmp, "bin")
            os.makedirs(fake_bin, exist_ok=True)
            os.symlink(sys.executable, os.path.join(fake_bin, "codex"))
            os.symlink(sys.executable, os.path.join(fake_bin, "node"))
            env["PATH"] = fake_bin + os.pathsep + env.get("PATH", "")
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-commands-only",
                "codex",
                "-c",
                (
                    "import json, os, subprocess; "
                    "codex_parent={k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY','http_proxy','https_proxy','REQUESTS_CA_BUNDLE','AGENT_JAIL_HTTP_PROXY','AGENT_JAIL_SOCKS_PROXY','AGENT_JAIL_SESSION_PROXY_ENV')}; "
                    "node_result=json.loads(subprocess.check_output(['node','-c',"
                    "\"import json, os, subprocess; "
                    "node_parent={k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY','http_proxy','https_proxy','REQUESTS_CA_BUNDLE','AGENT_JAIL_HTTP_PROXY','AGENT_JAIL_SOCKS_PROXY','AGENT_JAIL_SESSION_PROXY_ENV')}; "
                    "child=json.loads(subprocess.check_output(['bash','-lc',"
                    "\\\"python3 -c \\\\\\\"import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))\\\\\\\"\\\""
                    "], text=True)); "
                    "print(json.dumps({'node_parent': node_parent, 'child': child}, sort_keys=True))\""
                    "], text=True)); "
                    "print(json.dumps({'codex_parent': codex_parent, 'node_result': node_result}, sort_keys=True))"
                ),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        expected_clean = {
            "ALL_PROXY": None,
            "HTTPS_PROXY": None,
            "HTTP_PROXY": None,
            "SOCKS_PROXY": None,
            "REQUESTS_CA_BUNDLE": None,
            "http_proxy": None,
            "https_proxy": None,
            "AGENT_JAIL_HTTP_PROXY": None,
            "AGENT_JAIL_SOCKS_PROXY": None,
            "AGENT_JAIL_SESSION_PROXY_ENV": None,
        }
        self.assertEqual(values["codex_parent"], expected_clean)
        self.assertEqual(values["node_result"]["node_parent"], expected_clean)
        self.assertProxyUrl(values["node_result"]["child"]["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["node_result"]["child"]["HTTPS_PROXY"], "http")
        self.assertIsNone(values["node_result"]["child"]["ALL_PROXY"])
        self.assertProxyUrl(values["node_result"]["child"]["SOCKS_PROXY"], "socks5")

    def test_run_with_proxy_commands_only_does_not_proxy_non_shell_children(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-commands-only",
                "python3",
                "-c",
                (
                    "import json, subprocess; "
                    "child=json.loads(subprocess.check_output(['python3','-c',"
                    "\"import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))\""
                    "], text=True)); "
                    "print(json.dumps(child, sort_keys=True))"
                ),
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(
            json.loads(proc.stdout.strip()),
            {"ALL_PROXY": None, "HTTPS_PROXY": None, "HTTP_PROXY": None, "SOCKS_PROXY": None},
        )

    def test_run_with_proxy_mode_http_sets_only_http_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-mode",
                "http",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertProxyUrl(values["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["HTTPS_PROXY"], "http")
        self.assertIsNone(values["ALL_PROXY"])
        self.assertIsNone(values["SOCKS_PROXY"])

    def test_render_cap_launcher_embeds_repo_root_without_env_dependency(self):
        script = render_cap_launcher("/tmp/repo-root", "/usr/bin/python3")
        self.assertIn('REPO_ROOT="/tmp/repo-root"', script)
        self.assertIn('PYTHON_BIN="/usr/bin/python3"', script)
        self.assertNotIn("AGENT_JAIL_SOURCE_ROOT", script)
        self.assertIn('exec "$PYTHON_BIN" -m agent_jail.cap_cli "$@"', script)

    def test_run_with_proxy_mode_socks_sets_socks_and_all_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-mode",
                "socks",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertIsNone(values["HTTP_PROXY"])
        self.assertIsNone(values["HTTPS_PROXY"])
        self.assertProxyUrl(values["ALL_PROXY"], "socks5")
        self.assertProxyUrl(values["SOCKS_PROXY"], "socks5")

    def test_run_with_proxy_mode_codex_http_sets_only_http_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-mode",
                "codex-http",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertProxyUrl(values["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["HTTPS_PROXY"], "http")
        self.assertIsNone(values["ALL_PROXY"])
        self.assertIsNone(values["SOCKS_PROXY"])

    def test_run_with_proxy_mode_codex_http_native_sets_only_http_proxy_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--proxy-mode",
                "codex-http-native",
                sys.executable,
                "-c",
                "import json, os; print(json.dumps({k: os.environ.get(k) for k in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','SOCKS_PROXY')}, sort_keys=True))",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        values = json.loads(proc.stdout.strip())
        self.assertProxyUrl(values["HTTP_PROXY"], "http")
        self.assertProxyUrl(values["HTTPS_PROXY"], "http")
        self.assertIsNone(values["ALL_PROXY"])
        self.assertIsNone(values["SOCKS_PROXY"])

    def test_apply_target_env_profile_strips_inherited_codex_proxy_and_cert_noise(self):
        from agent_jail.main import apply_target_env_profile

        env = {
            "HTTP_PROXY": "http://127.0.0.1:5000",
            "HTTPS_PROXY": "http://127.0.0.1:5000",
            "ALL_PROXY": "socks5://127.0.0.1:5001",
            "SOCKS_PROXY": "socks5://127.0.0.1:5001",
            "AGENT_JAIL_HTTP_PROXY": "http://127.0.0.1:6000",
            "AGENT_JAIL_SOCKS_PROXY": "socks5://127.0.0.1:6001",
            "SSL_CERT_FILE": "/tmp/jail-cert.pem",
            "SSL_CERT_DIR": "/tmp/jail-certs",
            "REQUESTS_CA_BUNDLE": "/tmp/host-requests.pem",
            "CURL_CA_BUNDLE": "/tmp/host-curl.pem",
            "NODE_EXTRA_CA_CERTS": "/tmp/host-node.pem",
            "http_proxy": "http://host-proxy:8080",
            "https_proxy": "http://host-proxy:8080",
            "all_proxy": "socks5://host-proxy:1080",
            "socks_proxy": "socks5://host-proxy:1080",
        }
        apply_target_env_profile(env, ["/usr/local/bin/codex", "exec", "hi"], proxy_mode="hybrid")
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:5000")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:5000")
        self.assertEqual(env["ALL_PROXY"], "socks5://127.0.0.1:5001")
        self.assertEqual(env["SOCKS_PROXY"], "socks5://127.0.0.1:5001")
        self.assertEqual(env["SSL_CERT_FILE"], "/tmp/jail-cert.pem")
        self.assertEqual(env["SSL_CERT_DIR"], "/tmp/jail-certs")
        self.assertNotIn("REQUESTS_CA_BUNDLE", env)
        self.assertNotIn("CURL_CA_BUNDLE", env)
        self.assertNotIn("NODE_EXTRA_CA_CERTS", env)
        self.assertNotIn("http_proxy", env)
        self.assertNotIn("https_proxy", env)
        self.assertNotIn("all_proxy", env)
        self.assertNotIn("socks_proxy", env)

    def test_apply_target_env_profile_codex_http_clears_socks_and_cert_env(self):
        from agent_jail.main import apply_target_env_profile

        env = {
            "HTTP_PROXY": "http://127.0.0.1:5000",
            "HTTPS_PROXY": "http://127.0.0.1:5000",
            "ALL_PROXY": "socks5://127.0.0.1:5001",
            "SOCKS_PROXY": "socks5://127.0.0.1:5001",
            "SSL_CERT_FILE": "/tmp/jail-cert.pem",
            "SSL_CERT_DIR": "/tmp/jail-certs",
        }
        apply_target_env_profile(env, ["/usr/local/bin/codex", "exec", "hi"], proxy_mode="codex-http")
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:5000")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:5000")
        self.assertNotIn("ALL_PROXY", env)
        self.assertNotIn("SOCKS_PROXY", env)
        self.assertEqual(env["SSL_CERT_FILE"], "/tmp/jail-cert.pem")
        self.assertNotIn("SSL_CERT_DIR", env)

    def test_apply_target_env_profile_codex_without_proxy_prefers_native_trust(self):
        from agent_jail.main import apply_target_env_profile

        env = {
            "SSL_CERT_FILE": "/tmp/jail-cert.pem",
            "SSL_CERT_DIR": "/tmp/jail-certs",
        }
        apply_target_env_profile(env, ["/usr/local/bin/codex", "exec", "hi"], proxy_mode=None)
        self.assertNotIn("SSL_CERT_FILE", env)
        self.assertNotIn("SSL_CERT_DIR", env)

    def test_apply_target_env_profile_codex_without_proxy_keeps_generated_system_roots(self):
        from agent_jail.main import apply_target_env_profile

        env = {
            "SSL_CERT_FILE": "/tmp/macos-system-roots.pem",
            "AGENT_JAIL_SYSTEM_CERT_FILE": "/tmp/macos-system-roots.pem",
            "SSL_CERT_DIR": "/tmp/jail-certs",
        }
        apply_target_env_profile(env, ["/usr/local/bin/codex", "exec", "hi"], proxy_mode=None)
        self.assertEqual(env["SSL_CERT_FILE"], "/tmp/macos-system-roots.pem")
        self.assertNotIn("SSL_CERT_DIR", env)

    def test_apply_target_env_profile_codex_http_native_clears_socks_and_all_cert_env(self):
        from agent_jail.main import apply_target_env_profile

        env = {
            "HTTP_PROXY": "http://127.0.0.1:5000",
            "HTTPS_PROXY": "http://127.0.0.1:5000",
            "ALL_PROXY": "socks5://127.0.0.1:5001",
            "SOCKS_PROXY": "socks5://127.0.0.1:5001",
            "SSL_CERT_FILE": "/tmp/jail-cert.pem",
            "SSL_CERT_DIR": "/tmp/jail-certs",
        }
        apply_target_env_profile(env, ["/usr/local/bin/codex", "exec", "hi"], proxy_mode="codex-http-native")
        self.assertEqual(env["HTTP_PROXY"], "http://127.0.0.1:5000")
        self.assertEqual(env["HTTPS_PROXY"], "http://127.0.0.1:5000")
        self.assertNotIn("ALL_PROXY", env)
        self.assertNotIn("SOCKS_PROXY", env)
        self.assertNotIn("SSL_CERT_FILE", env)
        self.assertNotIn("SSL_CERT_DIR", env)

    def test_print_launch_env_writes_proxy_subset_to_stderr(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli(
                "run",
                "--proxy",
                "--print-launch-env",
                sys.executable,
                "-c",
                "print('ok')",
                env=env,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "ok")
        launch_env = json.loads(proc.stderr.strip())
        self.assertIn("HTTP_PROXY", launch_env)
        self.assertIn("HTTPS_PROXY", launch_env)

    def test_mounts_codex_claude_and_overwatchr_home_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".claude"))
            os.makedirs(os.path.join(real_home, ".overwatchr"))
            os.makedirs(os.path.join(real_home, "Library", "Keychains"))
            os.makedirs(os.path.join(real_home, "Library", "Preferences"))
            os.makedirs(os.path.join(real_home, "build"))
            os.makedirs(os.path.join(real_home, "workspace"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(jail_home, extra_home_mounts=[".overwatchr"])
                codex_link = os.path.islink(os.path.join(jail_home, ".codex"))
                claude_link = os.path.islink(os.path.join(jail_home, ".claude"))
                overwatchr_link = os.path.islink(os.path.join(jail_home, ".overwatchr"))
                keychains_link = os.path.islink(
                    os.path.join(jail_home, "Library", "Keychains")
                )
                preferences_link = os.path.islink(
                    os.path.join(jail_home, "Library", "Preferences")
                )
                build_link = os.path.islink(os.path.join(jail_home, "build"))
                workspace_link = os.path.islink(os.path.join(jail_home, "workspace"))
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            self.assertEqual(
                {m["source"] for m in mounts},
                {
                    os.path.join(real_home, ".codex"),
                    os.path.join(real_home, ".claude"),
                    os.path.join(real_home, ".overwatchr"),
                    os.path.join(real_home, "Library", "Keychains"),
                    os.path.join(real_home, "Library", "Preferences"),
                },
            )
            self.assertTrue(codex_link)
            self.assertTrue(claude_link)
            self.assertTrue(overwatchr_link)
            self.assertTrue(keychains_link)
            self.assertTrue(preferences_link)
            self.assertTrue(build_link)
            self.assertTrue(workspace_link)

    def test_can_disable_codex_and_claude_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".claude"))
            os.makedirs(os.path.join(real_home, ".overwatchr"))
            os.makedirs(os.path.join(real_home, "build"))
            os.makedirs(os.path.join(real_home, "workspace"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(
                    jail_home,
                    mount_codex_home=False,
                    mount_claude_home=False,
                    extra_home_mounts=[".overwatchr"],
                )
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            self.assertEqual(mounts, [{"source": os.path.join(real_home, ".overwatchr"), "target": os.path.join(jail_home, ".overwatchr"), "mode": "rw"}])
            self.assertTrue(os.path.islink(os.path.join(jail_home, ".overwatchr")))
            self.assertTrue(os.path.islink(os.path.join(jail_home, "build")))
            self.assertTrue(os.path.islink(os.path.join(jail_home, "workspace")))

    def test_prepare_home_mounts_accepts_configured_nested_home_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            nested_source = os.path.join(real_home, ".config", "opencode")
            os.makedirs(nested_source)
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(
                    jail_home,
                    mount_codex_home=False,
                    mount_claude_home=False,
                    extra_home_mounts=[".config/opencode"],
                )
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            self.assertIn(
                {"source": nested_source, "target": os.path.join(jail_home, ".config", "opencode"), "mode": "rw"},
                mounts,
            )
            self.assertTrue(os.path.islink(os.path.join(jail_home, ".config", "opencode")))

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

    def test_prepare_home_mounts_keeps_existing_matching_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            source = os.path.join(real_home, ".codex")
            target = os.path.join(jail_home, ".codex")
            os.makedirs(source)
            os.makedirs(jail_home)
            os.symlink(source, target)
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
            self.assertEqual(len(mounts), 1)
            self.assertEqual(mounts[0]["source"], source)
            self.assertEqual(os.path.realpath(target), os.path.realpath(source))

    def test_prepare_home_mounts_links_build_and_workspace_when_present(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            build_dir = os.path.join(real_home, "build")
            workspace_dir = os.path.join(real_home, "workspace")
            os.makedirs(build_dir)
            os.makedirs(workspace_dir)
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                prepare_home_mounts(jail_home, mount_codex_home=False, mount_claude_home=False)
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            self.assertEqual(os.path.realpath(os.path.join(jail_home, "build")), os.path.realpath(build_dir))
            self.assertEqual(os.path.realpath(os.path.join(jail_home, "workspace")), os.path.realpath(workspace_dir))

    def test_run_provides_python_shim(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli("run", "python", "-c", "print('shim-ok')", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(proc.stdout.strip(), "shim-ok")

    def test_run_aborts_when_kill_switch_exists_before_launch(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            kill_switch = os.path.join(tmp, "stop")
            open(kill_switch, "w", encoding="utf-8").close()
            proc = self.run_cli("run", "--kill-switch", kill_switch, sys.executable, "-c", "print('nope')", env=env)
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("kill switch", proc.stderr.lower())

    def test_monitor_reads_runtime_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            events_dir = os.path.join(tmp, "events")
            os.makedirs(events_dir)
            log_path = os.path.join(events_dir, "session.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write('{"action":"allow","category":"read-only","raw":"git status"}\n')
            runtime_path = os.path.join(tmp, "runtime.json")
            with open(runtime_path, "w", encoding="utf-8") as handle:
                json.dump({"events_log": log_path, "events_socket": None}, handle)
            proc = self.run_cli("monitor", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("[ALLOW][read-only] git status", proc.stdout)

    def test_monitor_reads_all_active_session_logs_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            events_dir = os.path.join(tmp, "events")
            runtimes_dir = os.path.join(tmp, "runtimes")
            os.makedirs(events_dir)
            os.makedirs(runtimes_dir)
            log_a = os.path.join(events_dir, "session-a.jsonl")
            log_b = os.path.join(events_dir, "session-b.jsonl")
            with open(log_a, "w", encoding="utf-8") as handle:
                handle.write('{"action":"allow","category":"read-only","raw":"git status","session":"session-a"}\n')
            with open(log_b, "w", encoding="utf-8") as handle:
                handle.write('{"action":"allow","category":"general","raw":"tree -L 2","session":"session-b"}\n')
            with open(os.path.join(runtimes_dir, "session-a.json"), "w", encoding="utf-8") as handle:
                json.dump({"active": True, "events_log": log_a, "events_socket": None, "session": "session-a"}, handle)
            with open(os.path.join(runtimes_dir, "session-b.json"), "w", encoding="utf-8") as handle:
                json.dump({"active": True, "events_log": log_b, "events_socket": None, "session": "session-b"}, handle)
            proc = self.run_cli("monitor", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("[ALLOW][read-only][session-a] git status", proc.stdout)
        self.assertIn("[ALLOW][general][session-b] tree -L 2", proc.stdout)

    def test_monitor_can_filter_specific_sessions(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            events_dir = os.path.join(tmp, "events")
            runtimes_dir = os.path.join(tmp, "runtimes")
            os.makedirs(events_dir)
            os.makedirs(runtimes_dir)
            log_a = os.path.join(events_dir, "session-a.jsonl")
            log_b = os.path.join(events_dir, "session-b.jsonl")
            with open(log_a, "w", encoding="utf-8") as handle:
                handle.write('{"action":"allow","category":"read-only","raw":"git status","session":"session-a"}\n')
            with open(log_b, "w", encoding="utf-8") as handle:
                handle.write('{"action":"allow","category":"general","raw":"tree -L 2","session":"session-b"}\n')
            with open(os.path.join(runtimes_dir, "session-a.json"), "w", encoding="utf-8") as handle:
                json.dump({"active": True, "events_log": log_a, "events_socket": None, "session": "session-a"}, handle)
            with open(os.path.join(runtimes_dir, "session-b.json"), "w", encoding="utf-8") as handle:
                json.dump({"active": True, "events_log": log_b, "events_socket": None, "session": "session-b"}, handle)
            proc = self.run_cli("monitor", "--session", "session-b", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertNotIn("git status", proc.stdout)
        self.assertIn("[ALLOW][general][session-b] tree -L 2", proc.stdout)

    def test_cleanup_removes_stale_runtime_logs_and_backups(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            events_root = os.path.join(tmp, "events")
            runtimes_root = os.path.join(tmp, "runtimes")
            os.makedirs(events_root)
            os.makedirs(runtimes_root)
            stale_log = os.path.join(events_root, "stale.jsonl")
            active_log = os.path.join(events_root, "active.jsonl")
            stale_runtime = os.path.join(runtimes_root, "stale.json")
            active_runtime = os.path.join(runtimes_root, "active.json")
            backup = os.path.join(tmp, "config.json.agent-jail-backup-20260403120000")
            for path in (stale_log, active_log, backup):
                with open(path, "w", encoding="utf-8") as handle:
                    handle.write("x")
            with open(stale_runtime, "w", encoding="utf-8") as handle:
                json.dump({"active": False, "events_log": stale_log}, handle)
            with open(active_runtime, "w", encoding="utf-8") as handle:
                json.dump({"active": True, "events_log": active_log}, handle)
            old = time.time() - 10 * 86400
            for path in (stale_log, stale_runtime, backup):
                os.utime(path, (old, old))
            proc = self.run_cli("cleanup", "--json", env=env)
            self.assertEqual(proc.returncode, 0, proc.stderr)
            result = json.loads(proc.stdout)
            self.assertEqual(result["runtime_records"], 1)
            self.assertEqual(result["event_logs"], 1)
            self.assertEqual(result["backups"], 1)
            self.assertFalse(os.path.exists(stale_runtime))
            self.assertFalse(os.path.exists(stale_log))
            self.assertFalse(os.path.exists(backup))
            self.assertTrue(os.path.exists(active_runtime))
            self.assertTrue(os.path.exists(active_log))

    def test_monitor_json_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "events.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write('{"action":"deny","category":"policy","raw":"opsctl status"}\n')
            proc = self.run_cli("monitor", "--json", "--log", log_path)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn('"action": "deny"', proc.stdout)

    def test_monitor_follow_switches_to_new_runtime_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            events_dir = os.path.join(tmp, "events")
            os.makedirs(events_dir)
            old_log = os.path.join(events_dir, "old.jsonl")
            new_log = os.path.join(events_dir, "new.jsonl")
            runtime_path = os.path.join(tmp, "runtime.json")
            with open(old_log, "w", encoding="utf-8") as handle:
                handle.write('{"action":"allow","category":"read-only","raw":"git status"}\n')
            with open(runtime_path, "w", encoding="utf-8") as handle:
                json.dump({"active": False, "events_log": old_log, "events_socket": None}, handle)
            proc = subprocess.Popen(
                [CLI, "monitor", "--follow"],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={**os.environ, "AGENT_JAIL_BACKEND": "host", **env},
            )
            try:
                time.sleep(0.3)
                with open(new_log, "w", encoding="utf-8") as handle:
                    handle.write('{"action":"allow","category":"general","raw":"tree -L 2"}\n')
                with open(runtime_path, "w", encoding="utf-8") as handle:
                    json.dump({"active": True, "events_log": new_log, "events_socket": None}, handle)
                deadline = time.time() + 3
                output = ""
                while time.time() < deadline:
                    line = proc.stdout.readline()
                    if line:
                        output += line
                        if "tree -L 2" in output:
                            break
                    else:
                        time.sleep(0.05)
                self.assertIn("tree -L 2", output)
            finally:
                proc.terminate()
                proc.wait(timeout=2)
                if proc.stdout:
                    proc.stdout.close()
                if proc.stderr:
                    proc.stderr.close()

    def test_suggest_rules_reads_event_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "events.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write(
                    '{"kind":"exec","action":"allow","template":"ls *","tool":"ls","verb":"exec","category":"read-only","raw":"ls src"}\n'
                )
                handle.write(
                    '{"kind":"exec","action":"allow","template":"ls *","tool":"ls","verb":"exec","category":"read-only","raw":"ls tests"}\n'
                )
            proc = self.run_cli("suggest-rules", "--log", log_path, env={"AGENT_JAIL_HOME": tmp})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("Suggestion Summary", proc.stdout)
        self.assertIn("Auto-Applicable", proc.stdout)
        self.assertIn("ls *", proc.stdout)
        self.assertIn("suggestions: 1", proc.stdout)

    def test_format_suggestion_report_groups_auto_and_review(self):
        report = _format_suggestion_report(
            [{"template": "ls *"}],
            [
                {
                    "auto_promote": True,
                    "rule": {
                        "tool": "ls",
                        "action": "exec",
                        "metadata": {"template": "ls *", "observations": 3, "confidence": 0.9, "source": "deterministic"},
                    },
                },
                {
                    "auto_promote": False,
                    "rule": {
                        "tool": "cat",
                        "action": "exec",
                        "metadata": {"template": "cat *", "observations": 2, "confidence": 0.7, "source": "azure_openai"},
                    },
                },
            ],
            [],
        )
        self.assertIn("Auto-Applicable", report)
        self.assertIn("Needs Review", report)
        self.assertIn("ls *", report)
        self.assertIn("cat *", report)

    def test_review_suggestions_interactively_applies_and_stores_skips(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            suggestions = [
                {
                    "auto_promote": True,
                    "rule": {
                        "kind": "exec",
                        "tool": "ls",
                        "action": "exec",
                        "allow": True,
                        "constraints": {},
                        "metadata": {"template": "ls *", "observations": 3, "confidence": 0.9, "source": "deterministic"},
                    },
                },
                {
                    "auto_promote": False,
                    "rule": {
                        "kind": "exec",
                        "tool": "cat",
                        "action": "exec",
                        "allow": True,
                        "constraints": {},
                        "metadata": {"template": "cat *", "observations": 2, "confidence": 0.7, "source": "deterministic"},
                    },
                },
            ]
            answers = iter(["a", "s"])
            result = _review_suggestions_interactively(store, suggestions, input_func=lambda prompt: next(answers))
            reloaded = PolicyStore(os.path.join(tmp, "policy.json"))
        self.assertEqual(len(result["approved"]), 1)
        self.assertEqual(len(result["skipped"]), 1)
        self.assertTrue(reloaded.match({"tool": "ls", "action": "exec"}))
        self.assertEqual(len(reloaded.suggestions), 1)
        self.assertEqual(reloaded.suggestions[0]["tool"], "cat")

    def test_review_list_reads_pending_reviews(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            policy_path = os.path.join(tmp, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "rules": [],
                        "pending_reviews": [
                            {
                                "id": "review-1",
                                "tool": "tree",
                                "action": "exec",
                                "raw": "tree -L 2",
                                "template": "tree *",
                            }
                        ],
                    },
                    handle,
                )
            proc = self.run_cli("review", "list", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertIn("review-1", proc.stdout)
        self.assertIn("tree *", proc.stdout)

    def test_review_list_hides_internal_noise_by_default(self):
        text = _format_review_list(
            [
                {"id": "review-1", "tool": "tree", "action": "exec", "template": "tree *", "reason": "safe", "confidence": 0.8, "source": "stub_jit"},
                {"id": "review-2", "tool": "codex", "action": "exec", "template": "codex *", "reason": "internal", "confidence": 0.8, "source": "stub_jit"},
            ],
            show_all=False,
            color=False,
        )
        self.assertIn("review-1", text)
        self.assertNotIn("review-2", text)
        self.assertIn("hidden internal reviews: 1", text)

    def test_review_list_shows_agent_launch_bypass_reviews(self):
        text = _format_review_list(
            [
                {
                    "id": "review-1",
                    "tool": "node",
                    "action": "exec",
                    "template": "node *",
                    "raw": "node /path/to/claude.js --allow-dangerously-skip-permissions",
                    "reason": "needs review",
                    "confidence": 0.8,
                    "source": "azure_openai_jit",
                },
            ],
            show_all=False,
            color=False,
        )
        self.assertIn("review-1", text)
        self.assertNotIn("hidden internal reviews", text)

    def test_review_list_hides_non_actionable_jit_noise_by_default(self):
        text = _format_review_list(
            [
                {
                    "id": "review-1",
                    "tool": "curl",
                    "action": "exec",
                    "template": "curl *",
                    "reason": "jit provider unavailable: missing azure openai config",
                    "confidence": 0.0,
                    "source": "jit",
                },
            ],
            show_all=False,
            color=False,
        )
        self.assertIn("no actionable pending reviews", text)
        self.assertNotIn("review-1", text)

    def test_review_list_can_show_internal_noise_with_all(self):
        text = _format_review_list(
            [
                {"id": "review-1", "tool": "codex", "action": "exec", "template": "codex *", "reason": "internal", "confidence": 0.8, "source": "stub_jit"},
            ],
            show_all=True,
            color=False,
        )
        self.assertIn("review-1", text)
        self.assertIn("reason: internal", text)

    def test_review_approve_adds_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            policy_path = os.path.join(tmp, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "rules": [],
                        "pending_reviews": [
                            {
                                "id": "review-1",
                                "tool": "tree",
                                "action": "exec",
                                "raw": "tree -L 2",
                                "rule": {
                                    "kind": "exec",
                                    "tool": "tree",
                                    "action": "exec",
                                    "allow": True,
                                    "constraints": {},
                                },
                            }
                        ],
                    },
                    handle,
                )
            proc = self.run_cli("review", "approve", "review-1", env=env)
            with open(policy_path, encoding="utf-8") as handle:
                policy = json.load(handle)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(policy["pending_reviews"], [])
        self.assertEqual(policy["rules"][0]["tool"], "tree")

    def test_review_approve_persists_delegate_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            policy_path = os.path.join(tmp, "policy.json")
            config_path = os.path.join(tmp, "config.json")
            script_path = "/Users/example/demo-project/scripts/service-health.sh"
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "rules": [],
                        "pending_reviews": [
                            {
                                "id": "review-1",
                                "kind": "delegate-config",
                                "tool": "service-health.sh",
                                "action": "secret-delegate",
                                "raw": f"{script_path} wifi-health --format text",
                                "template": script_path,
                                "script_path": script_path,
                                "secret_capability": "age_key_file",
                                "delegate": {
                                    "name": "local-secret-service-health-sh-age-key-file",
                                    "allowed_tools": [script_path],
                                    "allowed_secrets": ["age_key_file"],
                                    "mode": "execute",
                                },
                            }
                        ],
                    },
                    handle,
                )
            with open(config_path, "w", encoding="utf-8") as handle:
                json.dump({"delegates": []}, handle)
            proc = self.run_cli("review", "approve", "review-1", env=env)
            with open(policy_path, encoding="utf-8") as handle:
                policy = json.load(handle)
            with open(config_path, encoding="utf-8") as handle:
                config = json.load(handle)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(policy["pending_reviews"], [])
        self.assertEqual(config["delegates"][0]["name"], "local-secret-service-health-sh-age-key-file")
        self.assertEqual(config["delegates"][0]["allowed_tools"], [script_path])
        self.assertEqual(config["delegates"][0]["allowed_secrets"], ["age_key_file"])

    def test_review_reject_removes_pending_request(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            policy_path = os.path.join(tmp, "policy.json")
            with open(policy_path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "rules": [],
                        "pending_reviews": [
                            {
                                "id": "review-1",
                                "tool": "tree",
                                "action": "exec",
                                "raw": "tree -L 2",
                            }
                        ],
                    },
                    handle,
                )
            proc = self.run_cli("review", "reject", "review-1", env=env)
            with open(policy_path, encoding="utf-8") as handle:
                policy = json.load(handle)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertEqual(policy["pending_reviews"], [])

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

    def test_discover_cert_env_uses_existing_default_verify_paths(self):
        from agent_jail.main import discover_cert_env

        with tempfile.TemporaryDirectory() as tmp:
            cafile = os.path.join(tmp, "cert.pem")
            capath = os.path.join(tmp, "certs")
            open(cafile, "w", encoding="utf-8").close()
            os.mkdir(capath)
            verify_paths = os.pathconf if False else None
            fake = mock.Mock(cafile=cafile, capath=capath)
            with mock.patch("agent_jail.main.sys.platform", "linux"), mock.patch(
                "agent_jail.main.ssl.get_default_verify_paths", return_value=fake
            ):
                env = discover_cert_env()
        self.assertEqual(env["SSL_CERT_FILE"], cafile)
        self.assertEqual(env["SSL_CERT_DIR"], capath)

    def test_discover_cert_env_uses_only_cafile_on_macos(self):
        from agent_jail.main import discover_cert_env

        with tempfile.TemporaryDirectory() as tmp:
            cafile = os.path.join(tmp, "cert.pem")
            open(cafile, "w", encoding="utf-8").close()
            fake = mock.Mock(cafile=cafile, capath=os.path.join(tmp, "certs"))
            with mock.patch("agent_jail.main.sys.platform", "darwin"), mock.patch(
                "agent_jail.main.ssl.get_default_verify_paths", return_value=fake
            ):
                env = discover_cert_env()
        self.assertEqual(env, {"SSL_CERT_FILE": cafile})

    def test_discover_macos_system_cert_env_exports_system_roots_pem(self):
        from agent_jail.main import DARWIN_SYSTEM_ROOT_PEM_NAME, discover_macos_system_cert_env

        completed = subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout="-----BEGIN CERTIFICATE-----\nabc\n-----END CERTIFICATE-----\n",
            stderr="",
        )
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "agent_jail.main.sys.platform", "darwin"
        ), mock.patch("agent_jail.main.subprocess.run", return_value=completed):
            env = discover_macos_system_cert_env(tmp)
            pem_path = os.path.join(tmp, DARWIN_SYSTEM_ROOT_PEM_NAME)
            self.assertEqual(
                env,
                {
                    "SSL_CERT_FILE": pem_path,
                    "AGENT_JAIL_SYSTEM_CERT_FILE": pem_path,
                },
            )
            with open(pem_path, encoding="utf-8") as handle:
                self.assertEqual(handle.read(), completed.stdout)

    def test_discover_macos_system_cert_env_ignores_empty_export(self):
        from agent_jail.main import discover_macos_system_cert_env

        completed = subprocess.CompletedProcess(args=[], returncode=0, stdout="", stderr="")
        with tempfile.TemporaryDirectory() as tmp, mock.patch(
            "agent_jail.main.sys.platform", "darwin"
        ), mock.patch("agent_jail.main.subprocess.run", return_value=completed):
            env = discover_macos_system_cert_env(tmp)
        self.assertEqual(env, {})

    def test_discover_tty_env_collects_ctermid_and_ttynames(self):
        from agent_jail.main import discover_tty_env

        with mock.patch("agent_jail.main.os.ctermid", return_value="/dev/tty"), mock.patch(
            "agent_jail.main.os.ttyname",
            side_effect=["/dev/ttys001", OSError("no tty"), "/dev/ttys001"],
        ):
            env = discover_tty_env()
        self.assertIn("AGENT_JAIL_TTY_PATHS", env)
        self.assertEqual(
            env["AGENT_JAIL_TTY_PATHS"],
            '["/dev/fd", "/dev/null", "/dev/stderr", "/dev/stdin", "/dev/stdout", "/dev/tty", "/dev/ttys001"]',
        )
