import socket
import urllib.error
import unittest

from agent_jail.rule_jit import JITRuleEngine


class JITRuleTests(unittest.TestCase):
    def test_general_low_risk_is_eligible(self):
        engine = JITRuleEngine({"jit_enabled": True})
        self.assertTrue(engine.eligible({"risk": "low", "category": "general"}))
        self.assertFalse(engine.eligible({"risk": "low", "category": "read-only"}))

    def test_validate_allow_response_builds_rule(self):
        engine = JITRuleEngine(
            {
                "jit_enabled": True,
                "confidence_threshold": 0.8,
            }
        )
        result = engine._validate_response(
            {
                "decision_hint": "allow",
                "confidence": 0.91,
                "generalized_template": "tree *",
                "candidate_rule": {
                    "tool": "tree",
                    "action": "exec",
                    "constraints": {},
                    "category": "general",
                    "risk": "low",
                },
                "reason": "Safe generalized inspection command.",
            },
            {"tool": "tree", "action": "exec"},
            "tree *",
        )
        self.assertEqual(result["decision_hint"], "allow")
        self.assertEqual(result["rule"]["tool"], "tree")

    def test_validate_low_confidence_response_falls_back_to_ask(self):
        engine = JITRuleEngine(
            {
                "jit_enabled": True,
                "confidence_threshold": 0.8,
            }
        )
        result = engine._validate_response(
            {
                "decision_hint": "allow",
                "confidence": 0.2,
                "generalized_template": "tree *",
                "candidate_rule": {
                    "tool": "tree",
                    "action": "exec",
                    "constraints": {},
                    "category": "general",
                    "risk": "low",
                },
                "reason": "Not confident enough.",
            },
            {"tool": "tree", "action": "exec"},
            "tree *",
        )
        self.assertEqual(result["decision_hint"], "ask")

    def test_missing_provider_config_reports_explicit_reason(self):
        engine = JITRuleEngine({"jit_enabled": True})
        result = engine._decide_remote({"tool": "tree", "action": "exec"}, "tree -L 2", {"risk": "low", "category": "general"}, "tree *", {})
        self.assertIn("missing azure openai config", result["reason"])

    def test_timeout_error_is_explicit(self):
        class _TimeoutEngine(JITRuleEngine):
            def _azure_enabled(self):
                return True

        engine = _TimeoutEngine(
            {
                "provider": "azure_openai",
                "endpoint_env": "AZURE_OPENAI_ENDPOINT",
                "api_key_env": "AZURE_OPENAI_API_KEY",
                "deployment_env": "AZURE_OPENAI_DEPLOYMENT",
                "jit_timeout_ms": 100,
            },
            environ={
                "AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com",
                "AZURE_OPENAI_API_KEY": "secret",
                "AZURE_OPENAI_DEPLOYMENT": "gpt-test",
            },
        )

        import urllib.request
        from unittest import mock

        with mock.patch.object(urllib.request, "urlopen", side_effect=urllib.error.URLError(socket.timeout())):
            result = engine._decide_remote({"tool": "tree", "action": "exec"}, "tree -L 2", {"risk": "low", "category": "general"}, "tree *", {})
        self.assertEqual(result["reason"], "jit request failed: timeout")

    def test_http_error_is_explicit(self):
        class _HttpEngine(JITRuleEngine):
            def _azure_enabled(self):
                return True

        engine = _HttpEngine(
            {
                "provider": "azure_openai",
                "endpoint_env": "AZURE_OPENAI_ENDPOINT",
                "api_key_env": "AZURE_OPENAI_API_KEY",
                "deployment_env": "AZURE_OPENAI_DEPLOYMENT",
            },
            environ={
                "AZURE_OPENAI_ENDPOINT": "https://example.openai.azure.com",
                "AZURE_OPENAI_API_KEY": "secret",
                "AZURE_OPENAI_DEPLOYMENT": "gpt-test",
            },
        )

        import urllib.request
        from unittest import mock

        http_error = urllib.error.HTTPError("https://example", 401, "Unauthorized", hdrs=None, fp=None)
        with mock.patch.object(urllib.request, "urlopen", side_effect=http_error):
            result = engine._decide_remote({"tool": "tree", "action": "exec"}, "tree -L 2", {"risk": "low", "category": "general"}, "tree *", {})
        self.assertEqual(result["reason"], "jit http error: 401")

    def test_stub_allow_builds_rule(self):
        engine = JITRuleEngine(
            {
                "provider": "stub",
                "jit_enabled": True,
                "stub_mode": "allow",
                "stub_confidence": 0.95,
                "confidence_threshold": 0.8,
            }
        )
        result = engine.decide({"tool": "tree", "action": "exec", "template": "tree *"}, "tree -L 2", {"risk": "low", "category": "general"}, "tree *")
        self.assertEqual(result["decision_hint"], "allow")
        self.assertEqual(result["rule"]["tool"], "tree")

    def test_stub_ask_creates_candidate_rule(self):
        engine = JITRuleEngine(
            {
                "provider": "stub",
                "jit_enabled": True,
                "stub_mode": "ask",
                "stub_confidence": 0.6,
            }
        )
        result = engine.decide({"tool": "python3", "action": "exec", "template": "python read-only subprocess script"}, "python3 -c ...", {"risk": "low", "category": "general"}, "python read-only subprocess script")
        self.assertEqual(result["decision_hint"], "ask")
        self.assertEqual(result["rule"]["constraints"]["template"], "python read-only subprocess script")

    def test_stub_reject_is_explicit(self):
        engine = JITRuleEngine(
            {
                "provider": "stub",
                "jit_enabled": True,
                "stub_mode": "reject",
                "stub_reason": "stubbed reject",
            }
        )
        result = engine.decide({"tool": "tree", "action": "exec"}, "tree -L 2", {"risk": "low", "category": "general"}, "tree *")
        self.assertEqual(result["decision_hint"], "reject")
        self.assertEqual(result["reason"], "stubbed reject")
