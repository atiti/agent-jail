import json
import os
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock

from agent_jail.main import _format_suggestion_report, _review_suggestions_interactively
from agent_jail.policy import PolicyStore

ROOT = os.path.dirname(os.path.dirname(__file__))
CLI = os.path.join(ROOT, "agent-jail")


class CLITests(unittest.TestCase):
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

    def test_run_returns_127_for_missing_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            env = os.environ.copy()
            env["AGENT_JAIL_HOME"] = tmp
            proc = self.run_cli("run", "definitely-not-a-real-command-12345", env=env)
        self.assertEqual(proc.returncode, 127)
        self.assertIn("target command not found", proc.stderr.lower())

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
        self.assertTrue(config["defaults"]["run"]["allow_ops"])
        self.assertEqual(config["defaults"]["run"]["allow_delegates"], ["local-secrets"])
        self.assertEqual(config["defaults"]["run"]["project_mode"], "cwd")

    def test_mounts_codex_and_claude_home_by_default(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".claude"))
            os.makedirs(os.path.join(real_home, "build"))
            os.makedirs(os.path.join(real_home, "workspace"))
            old_home = os.environ.get("HOME")
            os.environ["HOME"] = real_home
            try:
                from agent_jail.main import prepare_home_mounts
                mounts = prepare_home_mounts(jail_home)
                codex_link = os.path.islink(os.path.join(jail_home, ".codex"))
                claude_link = os.path.islink(os.path.join(jail_home, ".claude"))
                build_link = os.path.islink(os.path.join(jail_home, "build"))
                workspace_link = os.path.islink(os.path.join(jail_home, "workspace"))
            finally:
                if old_home is None:
                    del os.environ["HOME"]
                else:
                    os.environ["HOME"] = old_home
            self.assertEqual({m["source"] for m in mounts}, {os.path.join(real_home, ".codex"), os.path.join(real_home, ".claude")})
            self.assertTrue(codex_link)
            self.assertTrue(claude_link)
            self.assertTrue(build_link)
            self.assertTrue(workspace_link)

    def test_can_disable_codex_and_claude_mounts(self):
        with tempfile.TemporaryDirectory() as tmp:
            real_home = os.path.join(tmp, "real-home")
            jail_home = os.path.join(tmp, "jail-home")
            os.makedirs(os.path.join(real_home, ".codex"))
            os.makedirs(os.path.join(real_home, ".claude"))
            os.makedirs(os.path.join(real_home, "build"))
            os.makedirs(os.path.join(real_home, "workspace"))
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
            self.assertTrue(os.path.islink(os.path.join(jail_home, "build")))
            self.assertTrue(os.path.islink(os.path.join(jail_home, "workspace")))

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
            with mock.patch("agent_jail.main.ssl.get_default_verify_paths", return_value=fake):
                env = discover_cert_env()
        self.assertEqual(env["SSL_CERT_FILE"], cafile)
        self.assertEqual(env["SSL_CERT_DIR"], capath)

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
