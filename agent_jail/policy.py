import json
import os
import uuid
from pathlib import Path


def default_policy_path():
    home = os.environ.get("AGENT_JAIL_HOME") or str(Path.home() / ".agent-jail")
    return os.path.join(home, "policy.json")


class PolicyStore:
    def __init__(self, path=None):
        self.path = path or default_policy_path()
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return {"rules": []}

    def save(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as handle:
            json.dump(self.data, handle, indent=2, sort_keys=True)

    @property
    def rules(self):
        return self.data.setdefault("rules", [])

    @property
    def suggestions(self):
        return self.data.setdefault("suggestions", [])

    @property
    def pending_reviews(self):
        return self.data.setdefault("pending_reviews", [])

    def match(self, subject, kind="exec"):
        for rule in self.rules:
            if rule.get("kind", "exec") != kind:
                continue
            if kind == "capability":
                if rule.get("name") != subject.get("name"):
                    continue
                return {"allow": bool(rule.get("allow", False)), "rule": rule}
            if kind == "network":
                if rule.get("host") != subject.get("host"):
                    continue
                if rule.get("port") not in (None, subject.get("port")):
                    continue
                return {"allow": bool(rule.get("allow", False)), "rule": rule}
            if rule.get("tool") != subject.get("tool"):
                continue
            if rule.get("action") != subject.get("action"):
                continue
            constraints = rule.get("constraints", {})
            if all(subject.get(key) == value for key, value in constraints.items()):
                return {"allow": bool(rule.get("allow", False)), "rule": rule}
        return None

    def learn(self, subject, kind="exec"):
        if kind == "capability":
            name = subject.get("name")
            if not name or self.match({"name": name}, kind="capability"):
                return
            self.rules.append({"kind": "capability", "name": name, "allow": True})
            self.save()
            return
        if kind == "network":
            host = subject.get("host")
            if not host or self.match({"host": host, "port": subject.get("port")}, kind="network"):
                return
            self.rules.append({"kind": "network", "host": host, "allow": True})
            self.save()
            return
        if subject.get("tool") == "git" and subject.get("action") == "push" and not subject.get("force", False):
            rule = {
                "tool": "git",
                "action": "push",
                "allow": True,
                "constraints": {"force": False},
            }
        else:
            return
        if not self.match({"tool": rule["tool"], "action": rule["action"], "force": False}):
            self.rules.append(rule)
            self.save()

    def add_rule(self, rule):
        subject = {
            "tool": rule.get("tool"),
            "action": rule.get("action"),
        }
        constraints = rule.get("constraints") or {}
        subject.update(constraints)
        if self.match(subject, kind=rule.get("kind", "exec")):
            return False
        self.rules.append(rule)
        self.save()
        return True

    def replace_suggestions(self, suggestions):
        self.data["suggestions"] = list(suggestions)
        self.save()

    def add_pending_review(self, review):
        item = dict(review)
        for existing in self.pending_reviews:
            if (
                existing.get("kind") == item.get("kind")
                and existing.get("tool") == item.get("tool")
                and existing.get("action") == item.get("action")
                and existing.get("template") == item.get("template")
            ):
                return existing
        item.setdefault("id", str(uuid.uuid4()))
        self.pending_reviews.append(item)
        self.save()
        return item

    def get_pending_review(self, review_id):
        for review in self.pending_reviews:
            if review.get("id") == review_id:
                return review
        return None

    def remove_pending_review(self, review_id):
        before = len(self.pending_reviews)
        self.data["pending_reviews"] = [review for review in self.pending_reviews if review.get("id") != review_id]
        changed = len(self.pending_reviews) != before
        if changed:
            self.save()
        return changed
