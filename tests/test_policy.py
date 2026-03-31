import json
import os
import tempfile
import unittest

from agent_jail.policy import PolicyStore


class PolicyTests(unittest.TestCase):
    def test_matching_rule_allows_safe_push(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump(
                    {
                        "rules": [
                            {
                                "tool": "git",
                                "action": "push",
                                "allow": True,
                                "constraints": {"force": False},
                            }
                        ]
                    },
                    handle,
                )
            store = PolicyStore(path)
            decision = store.match({"tool": "git", "action": "push", "force": False})
        self.assertTrue(decision["allow"])

    def test_learning_generates_non_force_push_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            store = PolicyStore(path)
            store.learn(
                {
                    "tool": "git",
                    "action": "push",
                    "flags": [],
                    "force": False,
                    "target": "origin/main",
                },
                kind="exec",
            )
            reloaded = PolicyStore(path)
            decision = reloaded.match({"tool": "git", "action": "push", "force": False})
        self.assertTrue(decision["allow"])
