import json
import os
import tempfile
import unittest
from unittest import mock

from agent_jail.policy import PolicyStore
from agent_jail.rule_suggestions import (
    AzureOpenAISuggester,
    apply_suggestions,
    _already_allowed,
    build_rule_suggestions,
    cluster_exec_events,
    deterministic_suggestions,
    validate_suggestion,
)


class RuleSuggestionTests(unittest.TestCase):
    def test_cluster_exec_events_groups_repeated_templates(self):
        clusters = cluster_exec_events(
            [
                {"kind": "exec", "action": "allow", "template": "ls *", "tool": "ls", "verb": "exec", "category": "read-only", "raw": "ls a"},
                {"kind": "exec", "action": "allow", "template": "ls *", "tool": "ls", "verb": "exec", "category": "read-only", "raw": "ls b"},
            ]
        )
        self.assertEqual(len(clusters), 1)
        self.assertEqual(clusters[0]["count"], 2)

    def test_deterministic_suggestions_produce_generalized_low_risk_rule(self):
        suggestions = deterministic_suggestions(
            [{"template": "ls *", "tool": "ls", "action": "exec", "category": "read-only", "count": 3, "examples": ["ls a"]}]
        )
        self.assertEqual(len(suggestions), 1)
        self.assertEqual(suggestions[0]["tool"], "ls")
        self.assertEqual(suggestions[0]["template"], "ls *")

    def test_validate_suggestion_blocks_niche_template(self):
        proposal = {
            "kind": "exec",
            "tool": "ls",
            "action": "exec",
            "template": "ls build/dist/out/test.bin",
            "category": "read-only",
            "risk": "low",
            "confidence": 0.9,
            "observations": 5,
        }
        self.assertIsNone(validate_suggestion(proposal, {"auto_promote_min_count": 3, "confidence_threshold": 0.8}))

    def test_validate_suggestion_marks_auto_promotable(self):
        proposal = {
            "kind": "exec",
            "tool": "ls",
            "action": "exec",
            "template": "ls *",
            "category": "read-only",
            "risk": "low",
            "confidence": 0.9,
            "observations": 5,
            "rationale": "Repeated low-risk listing pattern.",
        }
        rule, auto_promote = validate_suggestion(proposal, {"auto_promote_min_count": 3, "confidence_threshold": 0.8})
        self.assertEqual(rule["tool"], "ls")
        self.assertTrue(auto_promote)

    def test_apply_suggestions_adds_auto_promoted_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            applied = apply_suggestions(
                store,
                [
                    {
                        "auto_promote": True,
                        "rule": {
                            "kind": "exec",
                            "tool": "ls",
                            "action": "exec",
                            "allow": True,
                            "constraints": {},
                            "metadata": {"template": "ls *"},
                        },
                    }
                ],
                auto_only=True,
            )
            reloaded = PolicyStore(os.path.join(tmp, "policy.json"))
        self.assertEqual(len(applied), 1)
        self.assertTrue(reloaded.match({"tool": "ls", "action": "exec"}))

    def test_already_allowed_returns_true_for_matching_allow_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            store.add_rule(
                {
                    "kind": "exec",
                    "tool": "ls",
                    "action": "exec",
                    "allow": True,
                    "constraints": {},
                }
            )
            rule = {
                "kind": "exec",
                "tool": "ls",
                "action": "exec",
                "allow": True,
                "constraints": {},
            }
            self.assertTrue(_already_allowed(store, rule))

    def test_build_rule_suggestions_skips_existing_matching_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "events.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                for raw in ("ls src", "ls tests"):
                    handle.write(
                        json.dumps(
                            {
                                "kind": "exec",
                                "action": "allow",
                                "template": "ls *",
                                "tool": "ls",
                                "verb": "exec",
                                "category": "read-only",
                                "raw": raw,
                            }
                        )
                        + "\n"
                    )
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            store.add_rule(
                {
                    "kind": "exec",
                    "tool": "ls",
                    "action": "exec",
                    "allow": True,
                    "constraints": {},
                    "metadata": {"template": "ls *"},
                }
            )
            result = build_rule_suggestions(store, {"llm_policy": {}}, event_paths=[log_path], limit=10)
        self.assertEqual(result["clusters"][0]["template"], "ls *")
        self.assertEqual(result["suggestions"], [])

    def test_build_rule_suggestions_uses_azure_when_enabled(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_path = os.path.join(tmp, "events.jsonl")
            with open(log_path, "w", encoding="utf-8") as handle:
                handle.write(
                    json.dumps(
                        {
                            "kind": "exec",
                            "action": "allow",
                            "template": "ls *",
                            "tool": "ls",
                            "verb": "exec",
                            "category": "read-only",
                            "raw": "ls src",
                        }
                    )
                    + "\n"
                )
                handle.write(
                    json.dumps(
                        {
                            "kind": "exec",
                            "action": "allow",
                            "template": "ls *",
                            "tool": "ls",
                            "verb": "exec",
                            "category": "read-only",
                            "raw": "ls tests",
                        }
                    )
                    + "\n"
                )
            store = PolicyStore(os.path.join(tmp, "policy.json"))
            config = {
                "llm_policy": {
                    "provider": "azure_openai",
                    "endpoint_env": "AZURE_OPENAI_ENDPOINT",
                    "api_key_env": "AZURE_OPENAI_API_KEY",
                    "deployment_env": "AZURE_OPENAI_DEPLOYMENT",
                    "api_version": "2024-10-21",
                    "auto_promote_min_count": 2,
                    "confidence_threshold": 0.8,
                }
            }
            fake_env = {
                "AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com",
                "AZURE_OPENAI_API_KEY": "secret",
                "AZURE_OPENAI_DEPLOYMENT": "gpt-test",
            }
            with mock.patch.object(AzureOpenAISuggester, "enabled", return_value=True), mock.patch.object(
                AzureOpenAISuggester,
                "suggest",
                return_value=[
                    {
                        "kind": "exec",
                        "tool": "ls",
                        "action": "exec",
                        "template": "ls *",
                        "category": "read-only",
                        "risk": "low",
                        "confidence": 0.95,
                        "observations": 2,
                        "rationale": "Repeated broad listing pattern.",
                        "source": "azure_openai",
                    }
                ],
            ), mock.patch.dict(os.environ, fake_env, clear=False):
                result = build_rule_suggestions(store, config, event_paths=[log_path], limit=10)
        self.assertEqual(len(result["suggestions"]), 1)
        self.assertTrue(result["suggestions"][0]["auto_promote"])
