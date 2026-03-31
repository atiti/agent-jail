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
