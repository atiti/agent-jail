import os
import tempfile
import unittest

from agent_jail.broker import BrokerServer
from agent_jail.policy import PolicyStore


class _StubJIT:
    def __init__(self, result):
        self.result = result

    def eligible(self, verdict):
        return verdict.get("risk") == "low" and verdict.get("category") == "general"

    def decide(self, intent, raw, verdict, template, context=None):
        return self.result


class BrokerTests(unittest.TestCase):
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
