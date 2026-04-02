import json
import os
import tempfile
import threading
import time
import unittest
from unittest import mock

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

    def test_save_is_atomic_during_concurrent_reload(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, "policy.json")
            with open(path, "w", encoding="utf-8") as handle:
                json.dump({"rules": []}, handle)

            store = PolicyStore(path)
            store.rules.append({"tool": "tree", "action": "exec", "allow": True, "constraints": {}})

            started = threading.Event()
            release = threading.Event()
            real_dump = json.dump

            def slow_dump(data, handle, *args, **kwargs):
                handle.write("{")
                handle.flush()
                started.set()
                self.assertTrue(release.wait(timeout=1.0))
                handle.seek(0)
                handle.truncate()
                return real_dump(data, handle, *args, **kwargs)

            worker = threading.Thread(target=store.save)
            with mock.patch("agent_jail.policy.json.dump", side_effect=slow_dump):
                worker.start()
                self.assertTrue(started.wait(timeout=1.0))
                reloaded = PolicyStore(path)
                self.assertEqual(reloaded.data, {"rules": []})
                release.set()
                worker.join(timeout=1.0)
            self.assertFalse(worker.is_alive())

            reloaded = PolicyStore(path)
            decision = reloaded.match({"tool": "tree", "action": "exec"})
        self.assertTrue(decision["allow"])
