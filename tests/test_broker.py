import json
import os
import tempfile
import threading
import time
import unittest

from agent_jail.broker import BrokerServer, normalize
from agent_jail.events import EventSink
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

    def test_jit_emits_monitor_events_for_llm_evaluation(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            log_path = os.path.join(tmp, "events.jsonl")
            sink = EventSink(log_path, default_fields={"session": "session-test"})
            sink.start()
            try:
                broker = BrokerServer(
                    os.path.join(tmp, "broker.sock"),
                    store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.4,
                        "reason": "Unknown low-impact command.",
                        "source": "stub_jit",
                        "cached": False,
                    }
                ),
                event_sink=sink,
                review_wait_timeout=0.2,
            )
                result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
            finally:
                sink.close()
            with open(log_path, encoding="utf-8") as handle:
                events = [json.loads(line) for line in handle]
        self.assertEqual(result["decision"], "deny")
        jit_events = [event for event in events if event.get("category") == "jit"]
        self.assertEqual([event.get("phase") for event in jit_events], ["start", "result"])
        self.assertEqual(jit_events[1].get("decision_hint"), "ask")
        self.assertEqual(jit_events[1].get("source"), "stub_jit")
        self.assertFalse(jit_events[1].get("cached"))

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
                review_wait_timeout=0.2,
            )
            result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("jit-review-timeout", result["reason"])
        self.assertEqual(len(store.pending_reviews), 1)

    def test_jit_provider_failures_do_not_create_pending_reviews(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.0,
                        "reason": "jit provider unavailable: missing azure openai config",
                    }
                ),
                review_wait_timeout=0.2,
            )
            result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("jit-unreviewable", result["reason"])
        self.assertEqual(len(store.pending_reviews), 0)

    def test_jit_zero_confidence_ask_does_not_create_pending_review(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                jit_engine=_StubJIT(
                    {
                        "decision_hint": "ask",
                        "confidence": 0.0,
                        "reason": "unknown low-impact command",
                    }
                ),
                review_wait_timeout=0.2,
            )
            result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("jit-unreviewable", result["reason"])
        self.assertEqual(len(store.pending_reviews), 0)

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
                review_wait_timeout=0.2,
            )
            first = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
            second = broker.handle({"type": "exec", "argv": ["tree", "-L", "3"], "raw": "tree -L 3", "cwd": tmp})
        self.assertEqual(len(store.pending_reviews), 1)
        self.assertIn(store.pending_reviews[0]["id"], first["reason"])
        self.assertIn(store.pending_reviews[0]["id"], second["reason"])

    def test_jit_waits_for_manual_review_approval(self):
        with tempfile.TemporaryDirectory() as tmp:
            pending_added = threading.Event()

            class _HookedPolicyStore(PolicyStore):
                def add_pending_review(self, review):
                    item = super().add_pending_review(review)
                    pending_added.set()
                    return item

            store = _HookedPolicyStore(os.path.join(tmp, "policy.json"))
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
                review_wait_timeout=1.0,
            )
            result_box = {}

            def run_handle():
                try:
                    result_box["result"] = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
                except Exception as exc:  # pragma: no cover - defensive capture for threaded test visibility
                    result_box["error"] = exc

            thread = threading.Thread(target=run_handle)
            thread.start()
            self.assertTrue(pending_added.wait(timeout=5.0))
            store.reload()
            pending = store.pending_reviews[0]
            store.add_rule(pending["rule"])
            store.remove_pending_review(pending["id"])
            thread.join()
            self.assertNotIn("error", result_box)
        self.assertEqual(result_box["result"]["decision"], "allow")
        self.assertIn("review-approved", result_box["result"]["reason"])

    def test_jit_waits_for_manual_review_rejection(self):
        with tempfile.TemporaryDirectory() as tmp:
            pending_added = threading.Event()

            class _HookedPolicyStore(PolicyStore):
                def add_pending_review(self, review):
                    item = super().add_pending_review(review)
                    pending_added.set()
                    return item

            store = _HookedPolicyStore(os.path.join(tmp, "policy.json"))
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
                review_wait_timeout=1.0,
            )
            result_box = {}

            def run_handle():
                try:
                    result_box["result"] = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
                except Exception as exc:  # pragma: no cover - defensive capture for threaded test visibility
                    result_box["error"] = exc

            thread = threading.Thread(target=run_handle)
            thread.start()
            self.assertTrue(pending_added.wait(timeout=5.0))
            store.reload()
            pending = store.pending_reviews[0]
            store.remove_pending_review(pending["id"])
            thread.join()
            self.assertNotIn("error", result_box)
        self.assertEqual(result_box["result"]["decision"], "deny")
        self.assertIn("jit-review-rejected", result_box["result"]["reason"])

    def test_jit_waits_for_manual_review_timeout(self):
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
                review_wait_timeout=0.2,
            )
            result = broker.handle({"type": "exec", "argv": ["tree", "-L", "2"], "raw": "tree -L 2", "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("jit-review-timeout", result["reason"])

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
                review_wait_timeout=0.2,
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
        self.assertIn("jit-review-timeout", result["reason"])
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
                        "operations",
                    ],
                    "raw": "python3 /Users/example/.codex/skills/ati-cto/scripts/ati_cto_brief.py --local-only --scope operations",
                    "cwd": tmp,
                }
            )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["reason"], "local ati-cto brief generation script")

    def test_secret_capability_guides_to_matching_local_script_delegate(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = os.path.join(tmp, "wifi-health.sh")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nprintf '%s\\n' \"$AGE_KEY_FILE\"\n")
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                secrets={"age_key_file": {"env": {"AGE_KEY_FILE": "~/.keys.txt"}}},
                delegates=[
                    {
                        "name": "ops",
                        "executor": "/usr/local/bin/delegate-exec",
                        "allowed_tools": ["opsctl"],
                        "allowed_secrets": ["age_key_file"],
                    },
                    {
                        "name": "local-secrets",
                        "executor": "/usr/local/bin/delegate-exec",
                        "allowed_tools": [script_path],
                        "allowed_secrets": ["age_key_file"],
                    },
                ],
            )
            result = broker.handle({"type": "exec", "argv": [script_path], "raw": script_path, "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("agent-jail-cap delegate local-secrets", result["reason"])
        self.assertIn(f"rerun: agent-jail-cap delegate local-secrets {script_path}", result["reason"])

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
                secrets={"age_key_file": {"env": {"AGE_KEY_FILE": "~/.config/agent-jail-demo/age-keys.txt"}}},
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

    def test_secret_capability_creates_pending_delegate_review_for_local_script(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = os.path.join(tmp, "wifi-health.sh")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nprintf '%s\\n' \"$AGE_KEY_FILE\"\n")
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                secrets={"age_key_file": {"env": {"AGE_KEY_FILE": "~/.keys.txt"}}},
                delegates=[
                    {
                        "name": "ops",
                        "executor": "/usr/local/bin/delegate-exec",
                        "allowed_tools": ["opsctl"],
                        "allowed_secrets": ["age_key_file"],
                    }
                ],
            )
            result = broker.handle({"type": "exec", "argv": [script_path, "wifi-health"], "raw": f"{script_path} wifi-health", "cwd": tmp})
        self.assertEqual(result["decision"], "deny")
        self.assertIn("secret-delegate-review-required", result["reason"])
        self.assertIn(f"rerun after approval: agent-jail-cap delegate local-secret-wifi-health-sh-age-key-file {script_path} wifi-health", result["reason"])
        self.assertEqual(len(store.pending_reviews), 1)
        review = store.pending_reviews[0]
        self.assertEqual(review["kind"], "delegate-config")
        self.assertEqual(review["script_path"], script_path)
        self.assertEqual(review["secret_capability"], "age_key_file")
        self.assertEqual(review["delegate"]["allowed_tools"], [script_path])
        self.assertEqual(review["delegate"]["allowed_secrets"], ["age_key_file"])

    def test_secret_capability_guidance_prefers_script_path_over_bash_wrapper(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = os.path.join(tmp, "wifi-health.sh")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nprintf '%s\\n' \"$AGE_KEY_FILE\"\n")
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                secrets={"age_key_file": {"env": {"AGE_KEY_FILE": "~/.keys.txt"}}},
                delegates=[
                    {
                        "name": "local-secrets",
                        "executor": "/usr/local/bin/delegate-exec",
                        "allowed_tools": [script_path],
                        "allowed_secrets": ["age_key_file"],
                    }
                ],
            )
            result = broker.handle(
                {"type": "exec", "argv": ["bash", script_path, "wifi-health"], "raw": f"bash {script_path} wifi-health", "cwd": tmp}
            )
        self.assertEqual(result["decision"], "deny")
        self.assertIn(f"rerun: agent-jail-cap delegate local-secrets {script_path} wifi-health", result["reason"])
        self.assertNotIn("delegate local-secrets bash", result["reason"])

    def test_shell_syntax_check_bypasses_jit_force_low_risk(self):
        with tempfile.TemporaryDirectory() as tmp:
            script_path = os.path.join(tmp, "wifi-health.sh")
            with open(script_path, "w", encoding="utf-8") as handle:
                handle.write("#!/bin/sh\nprintf '%s\\n' \"$AGE_KEY_FILE\"\n")
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            broker = BrokerServer(
                os.path.join(tmp, "broker.sock"),
                store,
                secrets={"age_key_file": {"env": {"AGE_KEY_FILE": "~/.keys.txt"}}},
                llm_policy={"jit_enabled": True, "jit_force_low_risk": True},
            )
            result = broker.handle(
                {"type": "exec", "argv": ["bash", "-n", script_path], "raw": f"bash -n {script_path}", "cwd": tmp}
            )
        self.assertEqual(result["decision"], "allow")
        self.assertEqual(result["reason"], "shell syntax check")

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
