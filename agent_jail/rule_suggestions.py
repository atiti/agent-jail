import glob
import json
import os
import urllib.error
import urllib.request


LOW_RISK_CATEGORIES = {"read-only"}
BLOCKED_CATEGORIES = {
    "absolute-path-sensitive",
    "privilege-escalation",
    "sensitive-delegate",
    "sensitive-browser",
    "remote-exec",
    "destructive",
}


def default_event_paths(home):
    return sorted(glob.glob(os.path.join(home, "events", "*.jsonl")))


def load_events(paths, limit=None):
    events = []
    for path in paths:
        if not path or not os.path.exists(path):
            continue
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                events.append(json.loads(line))
    if limit is not None and limit > 0:
        return events[-limit:]
    return events


def cluster_exec_events(events):
    clusters = {}
    for event in events:
        if event.get("kind") != "exec":
            continue
        if event.get("action") not in {"allow", "ask"}:
            continue
        template = event.get("template")
        if not template:
            continue
        key = (template, event.get("tool"), event.get("verb"), event.get("category"))
        cluster = clusters.setdefault(
            key,
            {
                "template": template,
                "tool": event.get("tool"),
                "action": event.get("verb"),
                "category": event.get("category"),
                "examples": [],
                "count": 0,
            },
        )
        cluster["count"] += 1
        if len(cluster["examples"]) < 5:
            cluster["examples"].append(event.get("raw"))
    return sorted(clusters.values(), key=lambda item: (-item["count"], item["template"]))


def deterministic_suggestions(clusters):
    suggestions = []
    for cluster in clusters:
        template = cluster.get("template") or ""
        category = cluster.get("category")
        tool = cluster.get("tool")
        action = cluster.get("action")
        if cluster.get("count", 0) < 2:
            continue
        if category not in LOW_RISK_CATEGORIES:
            continue
        if not tool or not action:
            continue
        if "/" in template and "*" not in template:
            continue
        suggestions.append(
            {
                "kind": "exec",
                "tool": tool,
                "action": action,
                "constraints": {},
                "template": template,
                "category": category,
                "risk": "low",
                "confidence": 0.85,
                "observations": cluster["count"],
                "rationale": "Repeated low-risk command pattern observed.",
                "source": "deterministic",
            }
        )
    return suggestions


class AzureOpenAISuggester:
    def __init__(self, llm_policy, environ=None):
        self.config = llm_policy or {}
        self.environ = environ or os.environ

    def enabled(self):
        if self.config.get("provider") != "azure_openai":
            return False
        return bool(
            self.environ.get(self.config.get("endpoint_env", ""))
            and self.environ.get(self.config.get("api_key_env", ""))
            and self.environ.get(self.config.get("deployment_env", ""))
        )

    def suggest(self, clusters, existing_rules):
        endpoint = self.environ[self.config["endpoint_env"]].rstrip("/")
        api_key = self.environ[self.config["api_key_env"]]
        deployment = self.environ[self.config["deployment_env"]]
        api_version = self.config.get("api_version", "2024-10-21")
        url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={api_version}"
        schema_hint = {
            "suggestions": [
                {
                    "kind": "exec",
                    "tool": "ls",
                    "action": "exec",
                    "constraints": {},
                    "template": "ls *",
                    "category": "read-only",
                    "risk": "low",
                    "confidence": 0.9,
                    "observations": 3,
                    "rationale": "Generalized repeated low-risk listing pattern.",
                }
            ]
        }
        prompt = {
            "existing_rules": existing_rules,
            "clusters": clusters,
            "requirements": {
                "generalize": True,
                "reject_niche_rules": True,
                "auto_promote_only_low_risk": True,
                "blocked_categories": sorted(BLOCKED_CATEGORIES),
            },
            "response_schema_hint": schema_hint,
        }
        body = {
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "Return only valid JSON. Suggest generalized allow rules for repeated, low-risk command patterns. "
                        "Do not suggest privilege escalation, remote execution, secret access, networking exceptions, or destructive commands."
                    ),
                },
                {
                    "role": "user",
                    "content": json.dumps(prompt, sort_keys=True),
                },
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
        with urllib.request.urlopen(request, timeout=30) as response:
            payload = json.loads(response.read().decode("utf-8"))
        content = payload["choices"][0]["message"]["content"]
        parsed = json.loads(content)
        suggestions = parsed.get("suggestions", [])
        for item in suggestions:
            item.setdefault("source", "azure_openai")
        return suggestions


def validate_suggestion(proposal, llm_policy):
    if not isinstance(proposal, dict):
        return None
    if proposal.get("kind", "exec") != "exec":
        return None
    if proposal.get("risk") != "low":
        return None
    if proposal.get("category") not in LOW_RISK_CATEGORIES:
        return None
    if proposal.get("category") in BLOCKED_CATEGORIES:
        return None
    tool = proposal.get("tool")
    action = proposal.get("action")
    if not tool or not action:
        return None
    template = proposal.get("template") or ""
    if not template or ("/" in template and "*" not in template):
        return None
    if any(token in template for token in ("sudo", "doas", "ssh", "curl", "wget", "rm -rf /", "secrets", ".env")):
        return None
    confidence = float(proposal.get("confidence", 0))
    observations = int(proposal.get("observations", 0))
    min_count = int(llm_policy.get("auto_promote_min_count", 3))
    threshold = float(llm_policy.get("confidence_threshold", 0.8))
    validated = {
        "kind": "exec",
        "tool": tool,
        "action": action,
        "allow": True,
        "constraints": proposal.get("constraints") or {},
        "metadata": {
            "category": proposal.get("category"),
            "confidence": confidence,
            "observations": observations,
            "promotion_state": "suggested",
            "rationale": proposal.get("rationale", ""),
            "source": proposal.get("source", "unknown"),
            "template": template,
        },
    }
    auto_promote = observations >= min_count and confidence >= threshold
    return validated, auto_promote


def build_rule_suggestions(policy_store, config, event_paths=None, limit=None):
    llm_policy = config.get("llm_policy", {})
    home = os.environ.get("AGENT_JAIL_HOME") or os.path.join(os.path.expanduser("~"), ".agent-jail")
    paths = event_paths or default_event_paths(home)
    events = load_events(paths, limit=limit)
    clusters = cluster_exec_events(events)
    suggestions = deterministic_suggestions(clusters)
    adapter = AzureOpenAISuggester(llm_policy)
    if adapter.enabled() and clusters:
        try:
            suggestions = adapter.suggest(clusters, policy_store.rules)
        except (urllib.error.URLError, KeyError, ValueError, TimeoutError):
            pass
    validated = []
    for proposal in suggestions:
        result = validate_suggestion(proposal, llm_policy)
        if result is None:
            continue
        rule, auto_promote = result
        validated.append({"rule": rule, "auto_promote": auto_promote})
    return {"events": events, "clusters": clusters, "suggestions": validated}


def apply_suggestions(policy_store, suggestions, auto_only=False):
    applied = []
    stored = []
    for item in suggestions:
        rule = dict(item["rule"])
        metadata = dict(rule.get("metadata", {}))
        if item.get("auto_promote"):
            metadata["promotion_state"] = "auto-approved"
            if policy_store.add_rule({**rule, "metadata": metadata}):
                applied.append(rule)
        elif not auto_only:
            stored.append({**rule, "metadata": metadata})
    if stored or not auto_only:
        policy_store.replace_suggestions(stored)
    return applied
