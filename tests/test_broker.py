import os
import tempfile
import unittest

from agent_jail.broker import BrokerServer, normalize
from agent_jail.policy import PolicyStore


class _StubJIT:
    def __init__(self, result):
        self.result = result

    def should_attempt(self, verdict):
        return verdict.get("risk") == "low" and verdict.get("category") == "general"

    def decide(self, intent, raw, verdict, template, context=None):
        return self.result


class BrokerTests(unittest.TestCase):
    def test_normalize_generic_command_uses_exec_action(self):
        intent = normalize(["tree", "-L", "2"])
        self.assertEqual(intent["action"], "exec")
        self.assertEqual(intent["target"], "2")

    def test_jit_allow_adds_rule_and_allows_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "allow",
                        "confidence": 0.95,
                        "reason": "Safe generalized rule.",
                        "rule": {
                            "kind": "exec",
                            "tool": "tree",
                            "action": "exec",
                            "allow": True,
                            "constraints": {},
                            "metadata": {"template": "tree *"},
                        },
                    }
                ),
            )
            result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
        self.assertEqual(result["decision"], "allow")
        self.assertIn("jit-approved", result["reason"])
        self.assertTrue(store.match({"tool": "tree", "action": "exec"}))

    def test_jit_ask_denies_unknown_general_command(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.4,
                        "reason": "Unknown low-impact command.",
                    }
                ),
            )
            result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("jit-review-required", result["reason"])
        self.assertEqual(len(store.pending_reviews), 1)

    def test_jit_pending_reviews_are_deduplicated_by_template(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.4,
                        "reason": "Unknown low-impact command.",
                        "rule": {
                            "kind": "exec",
                            "tool": "tree",
                            "action": "exec",
                            "allow": True,
                            "constraints": {},
                            "metadata": {"template": "tree *"},
                        },
                    }
                ),
            )
            first = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
            second = broker.handle({"type": "exec", "argv": ["tree", "-L", "3"], "raw": "tree -L 3", "cwd": tmp})
        self.assertEqual(len(store.pending_reviews), 1)
        self.assertIn(store.pending_reviews[0]["id"], first["reason"])
        self.assertIn(store.pending_reviews[0]["id"], second["reason"])

    def test_jit_review_uses_semantic_template_for_python_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.4,
                        "reason": "Low-risk python inspection script.",
                        "rule": {
                            "kind": "exec",
                            "tool": "python3",
                            "action": "exec",
                            "allow": True,
                            "constraints": {},
                            "metadata": {"template": "python read-only subprocess script"},
                        },
                    }
                ),
            )
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": [
                        "sandbox-exec",
                        "-f",
                        "/tmp/jail.sb",
                        "/opt/homebrew/bin/python3",
                        "-c",
                        "import subprocess; subprocess.run(['tree', '-L', '2'])",
                    ],
                    "raw": "sandbox-exec -f /tmp/jail.sb /opt/homebrew/bin/python3 -c \"import subprocess; subprocess.run(['tree', '-L', '2'])\"",
                    "cwd": tmp,
                }
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("jit-review-required", result["reason"])
        self.assertEqual(store.pending_reviews[0]["tool"], "python3")
        self.assertEqual(store.pending_reviews[0]["template"], "python read-only subprocess script")
        self.assertEqual(store.pending_reviews[0]["rule"]["constraints"]["template"], "python read-only subprocess script")

    def test_policy_match_uses_semantic_template_for_python_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            store.add_rule(
                {
                    "kind": "exec",
                    "tool": "python3",
                    "action": "exec",
                    "allow": True,
                    "constraints": {"template": "python read-only subprocess script"},
                }
            )
            broker = BrokerServer(os.path.join(tmp, "broker.sock"), store, jit_engine=_StubJIT({"decision_hint": "ask"}))
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": [
                        "sandbox-exec",
                        "-f",
                        "/tmp/jail.sb",
                        "/opt/homebrew/bin/python3",
                        "-c",
                        "import subprocess; subprocess.run(['tree', '-L', '2'])",
                    ],
                    "raw": "sandbox-exec -f /tmp/jail.sb /opt/homebrew/bin/python3 -c \"import subprocess; subprocess.run(['tree', '-L', '2'])\"",
                    "cwd": tmp,
                }
            )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["reason"], "matched policy")

    def test_read_guard_denies_cat_outside_allowed_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.mkdir(repo)
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(os.path.join(tmp, "broker.sock"), store, mounts=[{"path": repo, "mode": "rw"}])
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": ["bash", "-c", "cat /etc/passwd"],
                    "raw": "bash -c cat /etc/passwd",
                    "cwd": repo,
                }
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("outside allowed roots", result["reason"])

    def test_ati_cto_brief_script_bypasses_jit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.1,
                        "reason": "should not be reached",
                    }
                ),
                mounts=[{"path": tmp, "mode": "rw"}],
            )
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": [
                        "python3",
                        "/Users/example/.codex/skills/ati-cto/scripts/ati_cto_brief.py",
                        "--local-only",
                        "--scope",
                        "privateinfra",
                    ],
                    "raw": "python3 /Users/example/.codex/skills/ati-cto/scripts/ati_cto_brief.py --local-only --scope privateinfra",
                    "cwd": tmp,
                }
            )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["reason"], "local ati-cto brief generation script")

    def test_read_guard_denies_python_literal_read_outside_allowed_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.mkdir(repo)
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(os.path.join(tmp, "broker.sock"), store, mounts=[{"path": repo, "mode": "rw"}])
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": ["python3", "-c", "print(open('/etc/passwd').read())"],
                    "raw": "python3 -c \"print(open('/etc/passwd').read())\"",
                    "cwd": repo,
                }
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("outside allowed roots", result["reason"])

    def test_secret_capability_denies_direct_python_env_access_with_delegate_guidance(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                secrets={"age_key_file": {"env": {"AGE_KEY_FILE": "~/.marksterctl/age/keys.txt"}}},
                delegates=[
                    {
                        "name": "ops",
                        "allowed_tools": ["python3"],
                        "allowed_secrets": ["age_key_file"],
                    }
                ],
            )
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": ["python3", "-c", "import os; print(os.environ['AGE_KEY_FILE'])"],
                    "raw": "python3 -c \"import os; print(os.environ['AGE_KEY_FILE'])\"",
                    "cwd": tmp,
                }
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("secret capability required", result["reason"])
        self.assertIn("agent-jail-cap delegate ops", result["reason"])

    def test_read_guard_denies_python_variable_read_outside_allowed_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.mkdir(repo)
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(os.path.join(tmp, "broker.sock"), store, mounts=[{"path": repo, "mode": "rw"}])
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": ["python3", "-c", 'p = "/etc/passwd"; print(open(p).read())'],
                    "raw": 'python3 -c "p = \\"/etc/passwd\\"; print(open(p).read())"',
                    "cwd": repo,
                }
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("outside allowed roots", result["reason"])

    def test_read_guard_denies_symlink_escape_outside_allowed_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            repo = os.path.join(tmp, "repo")
            os.mkdir(repo)
            link = os.path.join(repo, "passwd-link")
            os.symlink("/etc/passwd", link)
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(os.path.join(tmp, "broker.sock"), store, mounts=[{"path": repo, "mode": "rw"}])
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": ["cat", link],
                    "raw": f"cat {link}",
                    "cwd": repo,
                }
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn("outside allowed roots", result["reason"])

    def test_codex_bypass_flag_is_allowed_without_jit(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT({"decision_hint": "ask", "reason": "should not be used"}),
            )
            result = broker.handle(
                {
                    "type": "exec",
                    "argv": ["codex", "--dangerously-bypass-approvals-and-sandbox"],
                    "raw": "codex --dangerously-bypass-approvals-and-sandbox",
                    "cwd": tmp,
                }
            )
        self.assertEqual(result["decision"], "allow")
