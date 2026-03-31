import json
import os
import shlex
import socket
import sys
import threading
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer


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
    if tool in {"sh", "bash", "zsh"} and action == "command-string":
        script = intent.get("target") or ""
        if "curl " in script and "|" in script and any(shell in script for shell in ("bash", "sh")):
            return {"risk": "critical", "reason": "remote shell pipeline"}
    if tool == "git" and action in {"status", "fetch"}:
        return {"risk": "low", "reason": "safe git read"}
    if tool == "git" and action == "push" and intent.get("force"):
        return {"risk": "high", "reason": "force push"}
    if tool == "git" and action == "push":
        return {"risk": "medium", "reason": "git push"}
    if tool in {"chmod", "chown"} or raw.startswith("rm -rf"):
        return {"risk": "high", "reason": "destructive mutation"}
    return {"risk": "low", "reason": "default allow"}


class _Handler(StreamRequestHandler):
    def handle(self):
        line = self.rfile.readline()
        if not line:
            return
        request = json.loads(line.decode("utf-8"))
        response = self.server.broker.handle(request)
        self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))


class BrokerServer:
    def __init__(self, path, policy_store):
        self.path = path
        self.policy_store = policy_store
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
        if request.get("type") != "exec":
            return {"decision": "deny", "reason": "unsupported request"}
        argv = request["argv"]
        intent = normalize(argv)
        matched = self.policy_store.match(intent)
        raw = request.get("raw") or shlex.join(argv)
        if matched:
            decision = "allow" if matched["allow"] else "deny"
            self._log(decision.upper(), raw)
            return {"decision": decision, "reason": "matched policy"}
        verdict = classify(intent, argv)
        risk = verdict["risk"]
        if risk == "critical":
            self._log("DENY", raw)
            return {"decision": "deny", "reason": verdict["reason"]}
        if risk == "high":
            self.policy_store.learn(intent)
            self._log("ASK", raw)
            return {"decision": "allow", "reason": f"auto-approved: {verdict['reason']}"}
        if risk == "medium":
            self.policy_store.learn(intent)
        self._log("ALLOW", raw)
        return {"decision": "allow", "reason": verdict["reason"]}

    def _log(self, tag, raw):
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
