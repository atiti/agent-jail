import json
import os
import shlex
import socket
import sys
import threading
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer

from agent_jail.browser_proxy import run_browser_proxy
from agent_jail.ops_proxy import run_ops_proxy
from agent_jail.skills_proxy import run_skill_proxy

OPS_TOOLS = {"marksterctl", "privateinfractl"}
BROWSER_TOOLS = {"peekaboo", "playwright-cli", "screencog"}
READ_ONLY_TOOLS = {"pwd", "ls", "cat", "rg", "grep", "find", "ruby"}
MUTATING_TOOLS = {"mv", "cp", "mkdir", "touch", "sed", "tee"}
SENSITIVE_ABSOLUTE_PATHS = {
    "/usr/bin/ssh": "use mediated ops tooling instead of direct ssh",
    "/usr/local/bin/infra-runner-exec": "use agent-jail-cap ops instead of direct infra runner access",
}


def normalize(argv):
    tool = os.path.basename(argv[0]) if argv else ""
    flags = []
    action = ""
    target = None
    force = False
    if tool in {"sh", "bash", "zsh"} and len(argv) > 2 and argv[1] in {"-c", "-lc"}:
        action = "command-string"
        flags.append(argv[1].lstrip("-"))
        target = argv[2]
    else:
        for item in argv[1:]:
            if item.startswith("-"):
                flag = item.lstrip("-")
                flags.append(flag)
                if flag in {"f", "force"}:
                    force = True
            elif not action:
                action = item
            elif target is None:
                target = item
            elif tool == "git" and action == "push":
                target = f"{target}/{item}"
    return {"tool": tool, "action": action or "exec", "target": target, "flags": flags, "force": force}


def classify(intent, argv):
    raw = " ".join(argv)
    tool = intent["tool"]
    action = intent["action"]
    if tool in OPS_TOOLS:
        return {
            "risk": "high",
            "reason": f"direct ops tools are blocked; use agent-jail-cap ops {' '.join(argv)}",
            "category": "sensitive-ops",
        }
    if tool in BROWSER_TOOLS:
        return {
            "risk": "high",
            "reason": f"direct browser tools are blocked; use agent-jail-cap browser {tool} {action}",
            "category": "sensitive-browser",
        }
    if tool in {"sh", "bash", "zsh"} and action == "command-string":
        script = intent.get("target") or ""
        for sensitive_path, guidance in SENSITIVE_ABSOLUTE_PATHS.items():
            if sensitive_path in script:
                return {
                    "risk": "critical",
                    "reason": f"direct absolute-path access to {sensitive_path} is blocked; {guidance}",
                    "category": "absolute-path-sensitive",
                }
        if "curl " in script and "|" in script and any(shell in script for shell in ("bash", "sh")):
            return {"risk": "critical", "reason": "remote shell pipeline", "category": "remote-exec"}
    if tool == "git" and action in {"status", "fetch"}:
        return {"risk": "low", "reason": "safe git read", "category": "read-only"}
    if tool == "git" and action == "push" and intent.get("force"):
        return {"risk": "high", "reason": "force push", "category": "mutating"}
    if tool == "git" and action == "push":
        return {"risk": "medium", "reason": "git push", "category": "mutating"}
    if tool in {"chmod", "chown"} or raw.startswith("rm -rf"):
        return {"risk": "high", "reason": "destructive mutation", "category": "destructive"}
    if tool in READ_ONLY_TOOLS:
        return {"risk": "low", "reason": "read-only tool", "category": "read-only"}
    if tool in MUTATING_TOOLS:
        return {"risk": "medium", "reason": "mutating filesystem tool", "category": "mutating"}
    return {"risk": "low", "reason": "default allow", "category": "general"}


class _Handler(StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        if not line:
            return
        request = json.loads(line.decode("utf-8"))
        response = self.server.broker.handle(request)
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class BrokerServer:
    def __init__(self, path, policy_store, capabilities=None):
        self.path = path
        self.policy_store = policy_store
        self.capabilities = capabilities or {}
        self.server = None

    def serve_forever(self):
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        if os.path.exists(self.path):
            os.unlink(self.path)
        class Server(ThreadingUnixStreamServer):
            daemon_threads = True
            allow_reuse_address = True
        self.server = Server(self.path, _Handler)
        self.server.broker = self
        self.server.serve_forever(poll_interval=0.2)

    def close(self):
        if self.server:
            self.server.shutdown()
            self.server.server_close()
        if os.path.exists(self.path):
            os.unlink(self.path)

    def handle(self, request):
        req_type = request.get("type")
        if req_type == "capability":
            return self._handle_capability(request)
        if req_type != "exec":
            return {"decision": "deny", "reason": "unsupported request"}
        argv = request["argv"]
        intent = normalize(argv)
        matched = self.policy_store.match(intent)
        raw = request.get("raw") or shlex.join(argv)
        if matched:
            decision = "allow" if matched["allow"] else "deny"
            self._log(decision.upper(), raw, "policy")
            return {"decision": decision, "reason": "matched policy"}
        verdict = classify(intent, argv)
        risk = verdict["risk"]
        if risk == "critical":
            self._log("DENY", raw, verdict.get("category"))
            return {"decision": "deny", "reason": verdict["reason"]}
        if intent["tool"] in OPS_TOOLS or intent["tool"] in BROWSER_TOOLS:
            self._log("DENY", raw, verdict.get("category"))
            return {"decision": "deny", "reason": verdict["reason"]}
        if risk == "high":
            self.policy_store.learn(intent)
            self._log("ASK", raw, verdict.get("category"))
            return {"decision": "allow", "reason": f"auto-approved: {verdict['reason']}"}
        if risk == "medium":
            self.policy_store.learn(intent)
        self._log("ALLOW", raw, verdict.get("category"))
        return {"decision": "allow", "reason": verdict["reason"]}

    def _handle_capability(self, request):
        name = request.get("name")
        matched = self.policy_store.match({"name": name}, kind="capability")
        allowed = bool(self.capabilities.get(name))
        if matched is not None:
            allowed = allowed and matched["allow"]
        if not allowed:
            self._log("DENY", f"capability {name}", "capability")
            return {"decision": "deny", "reason": f"{name} capability denied"}
        if name == "ops_exec":
            result = run_ops_proxy(self.capabilities, request.get("payload", {}).get("command", []))
        elif name == "browser_automation":
            result = run_browser_proxy(self.capabilities, request.get("payload", {}))
        elif name == "skills_proxy":
            result = run_skill_proxy(self.capabilities, request.get("payload", {}))
        else:
            result = {"status": "ok", "name": name}
        self._log("ALLOW", f"capability {name}", "capability")
        return {"decision": "allow", "reason": "capability allowed", "result": result}

    def _log(self, tag, raw, category=None):
        if category:
            print(f"[{tag}][{category}] {raw}", file=sys.stderr, flush=True)
        else:
            print(f"[{tag}] {raw}", file=sys.stderr, flush=True)


def broker_request(sock_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(sock_path)
        client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        data = b""
        while not data.endswith(b"\n"):
            chunk = client.recv(65536)
            if not chunk:
                break
            data += chunk
    return json.loads(data.decode("utf-8"))
