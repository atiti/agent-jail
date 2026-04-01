import json
import os
import socket
import urllib.error
import urllib.request


BLOCKED_TOKENS = ("sudo", "doas", "ssh", "curl", "wget", ".env", "secrets", "rm -rf /")


class JITRuleEngine:
    def __init__(self, llm_policy, environ=None):
        self.config = llm_policy or {}
        self.environ = environ or os.environ
        self.cache = {}

    def enabled(self):
        return bool(self.config.get("jit_enabled"))

    def eligible(self, verdict):
        if not self.enabled():
            return False
        return verdict.get("risk") == "low" and verdict.get("category") == "general"

    def decide(self, intent, raw, verdict, template, context=None):
        key = (intent.get("tool"), intent.get("action"), template)
        cached = self.cache.get(key)
        if cached is not None:
            return cached
        result = self._decide_remote(intent, raw, verdict, template, context or {})
        self.cache[key] = result
        return result

    def _decide_remote(self, intent, raw, verdict, template, context):
        if self._stub_enabled():
            return self._decide_stub(intent, template)
        if not self._azure_enabled():
            return {
                "decision_hint": "ask",
                "confidence": 0.0,
                "reason": "jit provider unavailable: missing azure openai config",
                "template": template,
                "source": "jit",
            }
        endpoint = self.environ[self.config["endpoint_env"]].rstrip("/")
        api_key = self.environ[self.config["api_key_env"]]
        deployment = self.environ[self.config["deployment_env"]]
        api_version = self.config.get("api_version", "2024-10-21")
        url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
        prompt = {
            "intent": {
                "tool": intent.get("tool"),
                "action": intent.get("action"),
                "target": intent.get("target"),
                "flags": intent.get("flags", []),
                "template": intent.get("template"),
            },
            "raw": raw,
            "template": template,
            "risk": verdict.get("risk"),
            "category": verdict.get("category"),
            "cwd": context.get("cwd"),
            "requirements": {
                "allow_only_if_low_risk": True,
                "must_generalize": True,
                "reject_if_path_specific": True,
                "blocked_tokens": list(BLOCKED_TOKENS),
            },
            "response_schema_hint": {
                "decision_hint": "allow",
                "confidence": 0.91,
                "generalized_template": template,
                "candidate_rule": {
                    "kind": "exec",
                    "tool": intent.get("tool"),
                    "action": intent.get("action"),
                    "constraints": {"template": template} if intent.get("template") else {},
                    "category": "general",
                    "risk": "low",
                },
                "reason": "Safe generalized inspection command.",
            },
        }
        body = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return only valid JSON. Decide whether this low-impact command can be generalized into a safe allow rule. "
                        "If unsure, return decision_hint ask. Never allow privilege escalation, secrets, remote execution, or destructive behavior."
                    ),
                },
                {"role": "user", "content": json.dumps(prompt, sort_keys=True)},
            ],
            "response_format": {"type": "json_object"},
            "temperature": 0.1,
        }
        if self.config.get("model"):
            body["model"] = self.config["model"]
        request = urllib.request.Request(
            url,
            data=json.dumps(body).encode("utf-8"),
            headers={"Content-Type": "application/json", "api-key": api_key},
            method="POST",
        )
        timeout = max(float(self.config.get("jit_timeout_ms", 800)) / 1000.0, 0.1)
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            return {
                "decision_hint": "ask",
                "confidence": 0.0,
                "reason": f"jit http error: {exc.code}",
                "template": template,
                "source": "jit",
            }
        except urllib.error.URLError as exc:
            root = exc.reason
            if isinstance(root, socket.timeout):
                detail = "timeout"
            else:
                detail = str(root)
            return {
                "decision_hint": "ask",
                "confidence": 0.0,
                "reason": f"jit request failed: {detail}",
                "template": template,
                "source": "jit",
            }
        except TimeoutError:
            return {
                "decision_hint": "ask",
                "confidence": 0.0,
                "reason": "jit request failed: timeout",
                "template": template,
                "source": "jit",
            }
        except ValueError:
            return {
                "decision_hint": "ask",
                "confidence": 0.0,
                "reason": "jit response payload was not valid json",
                "template": template,
                "source": "jit",
            }
        content = payload["choices"][0]["message"]["content"]
        try:
            parsed = json.loads(content)
        except ValueError:
            return {
                "decision_hint": "ask",
                "confidence": 0.0,
                "reason": "jit response was not valid json",
                "template": template,
                "source": "jit",
            }
        return self._validate_response(parsed, intent, template)

    def _validate_response(self, parsed, intent, template):
        decision = parsed.get("decision_hint", "ask")
        confidence = float(parsed.get("confidence", 0.0))
        generalized_template = parsed.get("generalized_template") or template
        if any(token in generalized_template for token in BLOCKED_TOKENS):
            decision = "reject"
        if "/" in generalized_template and "*" not in generalized_template:
            decision = "ask"
        candidate = parsed.get("candidate_rule") or {}
        if decision == "allow":
            if candidate.get("tool") != intent.get("tool") or candidate.get("action") != intent.get("action"):
                decision = "ask"
            if candidate.get("risk") != "low":
                decision = "ask"
            if confidence < float(self.config.get("confidence_threshold", 0.8)):
                decision = "ask"
        result = {
            "decision_hint": decision,
            "confidence": confidence,
            "template": generalized_template,
            "reason": parsed.get("reason", ""),
            "source": "azure_openai_jit",
        }
        if candidate.get("tool") == intent.get("tool") and candidate.get("action") == intent.get("action"):
            constraints = candidate.get("constraints") or {}
            if intent.get("template"):
                constraints = dict(constraints)
                constraints.setdefault("template", generalized_template)
            result["rule"] = {
                "kind": "exec",
                "tool": candidate["tool"],
                "action": candidate["action"],
                "allow": True,
                "constraints": constraints,
                "metadata": {
                    "category": candidate.get("category", "general"),
                    "confidence": confidence,
                    "promotion_state": "jit-auto-approved",
                    "rationale": parsed.get("reason", ""),
                    "source": "azure_openai_jit",
                    "template": generalized_template,
                },
            }
        return result

    def _decide_stub(self, intent, template):
        mode = (self.config.get("stub_mode") or "ask").lower()
        confidence = float(self.config.get("stub_confidence", 0.95))
        reason = self.config.get("stub_reason") or f"stub {mode}"
        if mode == "reject":
            return {
                "decision_hint": "reject",
                "confidence": confidence,
                "reason": reason,
                "template": template,
                "source": "stub_jit",
            }
        candidate_rule = {
            "kind": "exec",
            "tool": intent.get("tool"),
            "action": intent.get("action"),
            "constraints": {"template": template} if intent.get("template") else {},
            "category": "general",
            "risk": "low",
        }
        if mode == "allow":
            return self._validate_response(
                {
                    "decision_hint": "allow",
                    "confidence": confidence,
                    "generalized_template": template,
                    "candidate_rule": candidate_rule,
                    "reason": reason,
                },
                intent,
                template,
            )
        return self._validate_response(
            {
                "decision_hint": "ask",
                "confidence": confidence,
                "generalized_template": template,
                "candidate_rule": candidate_rule,
                "reason": reason,
            },
            intent,
            template,
        )

    def _azure_enabled(self):
        if self.config.get("provider") != "azure_openai":
            return False
        return bool(
            self.environ.get(self.config.get("endpoint_env", ""))
            and self.environ.get(self.config.get("api_key_env", ""))
            and self.environ.get(self.config.get("deployment_env", ""))
        )

    def _stub_enabled(self):
        return self.config.get("provider") == "stub"
