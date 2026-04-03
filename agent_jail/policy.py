import json
import os
import tempfile
import threading
import uuid
from pathlib import Path


def default_policy_path():
    home = os.environ.get("AGENT_JAIL_STATE_HOME") or os.environ.get("AGENT_JAIL_HOME") or str(Path.home() / ".agent-jail")
    return os.path.join(home, "policy.json")


class PolicyStore:
    def __init__(self, path=None):
        self.path = path or default_policy_path()
        self._lock = threading.RLock()
        self.data = self._load()

    def _load(self):
        if os.path.exists(self.path):
            with open(self.path, "r", encoding="utf-8") as handle:
                return json.load(handle)
        return {"rules": []}

    def reload(self):
        with self._lock:
            self.data = self._load()
            return self.data

    def save(self):
        with self._lock:
            directory = os.path.dirname(self.path) or "."
            os.makedirs(directory, exist_ok=True)
            fd, tmp_path = tempfile.mkstemp(prefix=".policy-", suffix=".json", dir=directory)
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as handle:
                    json.dump(self.data, handle, indent=2, sort_keys=True)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.replace(tmp_path, self.path)
            finally:
                if os.path.exists(tmp_path):
                    os.unlink(tmp_path)

    @property
    def rules(self):
        with self._lock:
            return self.data.setdefault("rules", [])

    @property
    def suggestions(self):
        with self._lock:
            return self.data.setdefault("suggestions", [])

    @property
    def pending_reviews(self):
        with self._lock:
            return self.data.setdefault("pending_reviews", [])

    def match(self, subject, kind="exec"):
        with self._lock:
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
        with self._lock:
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
        with self._lock:
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

    def set_rule(self, rule):
        with self._lock:
            kind = rule.get("kind", "exec")
            replaced = False
            retained = []
            for existing in self.rules:
                if existing.get("kind", "exec") != kind:
                    retained.append(existing)
                    continue
                if kind == "network":
                    same = (
                        existing.get("host") == rule.get("host")
                        and existing.get("port") == rule.get("port")
                        and existing.get("scheme") == rule.get("scheme")
                    )
                elif kind == "capability":
                    same = existing.get("name") == rule.get("name")
                else:
                    same = (
                        existing.get("tool") == rule.get("tool")
                        and existing.get("action") == rule.get("action")
                        and (existing.get("constraints") or {}) == (rule.get("constraints") or {})
                    )
                if same:
                    replaced = True
                    continue
                retained.append(existing)
            retained.append(rule)
            self.data["rules"] = retained
            self.save()
            return replaced

    def replace_suggestions(self, suggestions):
        with self._lock:
            self.data["suggestions"] = list(suggestions)
            self.save()

    def add_pending_review(self, review):
        with self._lock:
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
        with self._lock:
            for review in self.pending_reviews:
                if review.get("id") == review_id:
                    return review
            return None

    def remove_pending_review(self, review_id):
        with self._lock:
            before = len(self.pending_reviews)
            self.data["pending_reviews"] = [review for review in self.pending_reviews if review.get("id") != review_id]
            changed = len(self.pending_reviews) != before
            if changed:
                self.save()
            return changed
