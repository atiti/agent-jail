import json
import os
import shlex
import socket
import sys
import threading
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer

from agent_jail.browser_proxy import run_browser_proxy
from agent_jail.delegate_proxy import run_delegate_proxy, stream_delegate_proxy
from agent_jail.events import render_event
from agent_jail.rule_jit import JITRuleEngine
from agent_jail.shell_analysis import ShellAnalysisError, analyze_shell_script
from agent_jail.skills_proxy import run_skill_proxy

BROWSER_TOOLS = {"peekaboo", "playwright-cli", "screencog"}
READ_ONLY_TOOLS = {"pwd", "ls", "cat", "rg", "grep", "find", "ruby", "head", "printenv"}
MUTATING_TOOLS = {"mv", "cp", "mkdir", "touch", "sed", "tee"}
DEFAULT_SENSITIVE_ABSOLUTE_PATHS = {
    "/usr/bin/env": "direct env-based dispatch is blocked; invoke wrapped tools by name instead",
    "/usr/bin/ssh": "use mediated ops tooling instead of direct ssh",
}
DEFAULT_PRIVILEGED_TOOLS = {"sudo", "doas"}
SENSITIVE_DENY_CATEGORIES = {
    "absolute-path-sensitive",
    "privilege-escalation",
    "sensitive-delegate",
    "sensitive-browser",
    "remote-exec",
}
SAFE_CLEANUP_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    ".tox",
}


def event_template(intent, verdict=None):
    tool = intent.get("tool") or ""
    action = intent.get("action") or "exec"
    category = (verdict or {}).get("category")
    if category == "cleanup":
        return "rm generated-artifacts"
    if tool == "git":
        return f"git {action} *"
    if action == "command-string":
        return f"{tool} -c <script>"
    return f"{tool} *"


def _delegate_tool_map(delegates):
    tool_map = {}
    for delegate in delegates or ():
        name = delegate.get("name")
        if not name:
            continue
        for tool in delegate.get("allowed_tools", []):
            tool_map.setdefault(tool, set()).add(name)
    return tool_map


def _delegate_executor_paths(delegates):
    paths = {}
    for delegate in delegates or ():
        executor = delegate.get("executor")
        if not executor:
            continue
        name = delegate.get("name") or "delegate"
        paths[executor] = f"use agent-jail-cap delegate {name} instead of direct delegate executor access"
    return paths


def _delegate_executor_tools(delegates):
    return {os.path.basename(path) for path in _delegate_executor_paths(delegates)}


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


def _safe_cleanup_target(target, cwd):
    if not cwd or not target:
        return False
    if any(ch in target for ch in "*?[]{}"):
        return False
    candidate = os.path.abspath(os.path.join(cwd, target))
    try:
        common = os.path.commonpath([cwd, candidate])
    except ValueError:
        return False
    if common != os.path.abspath(cwd):
        return False
    parts = [part for part in os.path.normpath(target).split(os.sep) if part not in {"", "."}]
    if any(part == ".." for part in parts):
        return False
    return any(part in SAFE_CLEANUP_NAMES for part in parts)


def _classify_safe_cleanup(intent, argv, context):
    if intent["tool"] != "rm":
        return None
    flags = set(intent.get("flags", []))
    if not ({"r", "f"} <= flags or {"rf"} <= flags or {"fr"} <= flags):
        return None
    targets = [item for item in argv[1:] if not item.startswith("-")]
    if not targets:
        return None
    cwd = context.get("cwd") if isinstance(context, dict) else None
    if all(_safe_cleanup_target(target, cwd) for target in targets):
        return {"risk": "low", "reason": "generated artifact cleanup", "category": "cleanup"}
    return None


def classify(intent, argv, delegates=None, context=None):
    raw = " ".join(argv)
    tool = intent["tool"]
    action = intent["action"]
    command_path = argv[0] if argv else ""
    sensitive_absolute_paths = dict(DEFAULT_SENSITIVE_ABSOLUTE_PATHS)
    sensitive_absolute_paths.update(_delegate_executor_paths(delegates))
    delegated_tools = _delegate_tool_map(delegates)
    privileged_tools = set(DEFAULT_PRIVILEGED_TOOLS)
    privileged_tools.update(_delegate_executor_tools(delegates))
    if os.path.isabs(command_path) and command_path in sensitive_absolute_paths:
        return {
            "risk": "critical",
            "reason": f"direct absolute-path access to {command_path} is blocked; {sensitive_absolute_paths[command_path]}",
            "category": "absolute-path-sensitive",
        }
    if tool in delegated_tools:
        delegate_names = sorted(delegated_tools[tool])
        delegate_name = delegate_names[0]
        return {
            "risk": "high",
            "reason": f"direct delegated tools are blocked; use agent-jail-cap delegate {delegate_name} {' '.join(argv)}",
            "category": "sensitive-delegate",
        }
    if tool in privileged_tools:
        return {
            "risk": "critical",
            "reason": "privilege escalation and delegate executors are blocked; use agent-jail-cap delegate <name> ...",
            "category": "privilege-escalation",
        }
    if tool in BROWSER_TOOLS:
        return {
            "risk": "high",
            "reason": f"direct browser tools are blocked; use agent-jail-cap browser {tool} {action}",
            "category": "sensitive-browser",
        }
    if tool in {"sh", "bash", "zsh"} and action == "command-string":
        script = intent.get("target") or ""
        for sensitive_path, guidance in sensitive_absolute_paths.items():
            if sensitive_path in script:
                return {
                    "risk": "critical",
                    "reason": f"direct absolute-path access to {sensitive_path} is blocked; {guidance}",
                    "category": "absolute-path-sensitive",
                }
        try:
            analysis = analyze_shell_script(script)
        except ShellAnalysisError:
            return {"risk": "critical", "reason": "unparseable shell command", "category": "shell-parse"}
        for pipeline in analysis["pipelines"]:
            tools = [os.path.basename(command[0]) for command in pipeline if command]
            if any(name in {"curl", "wget"} for name in tools) and any(name in {"bash", "sh", "zsh"} for name in tools):
                return {"risk": "critical", "reason": "remote shell pipeline", "category": "remote-exec"}
        highest = None
        risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        for command in analysis["commands"]:
            nested_intent = normalize(command)
            verdict = classify(nested_intent, command, delegates=delegates)
            if verdict["category"] in SENSITIVE_DENY_CATEGORIES:
                return verdict
            if highest is None or risk_rank[verdict["risk"]] > risk_rank[highest["risk"]]:
                highest = verdict
        if highest is not None:
            return highest
    cleanup_verdict = _classify_safe_cleanup(intent, argv, context or {})
    if cleanup_verdict is not None:
        return cleanup_verdict
    if tool == "git" and action in {"status", "fetch"}:
        return {"risk": "low", "reason": "safe git read", "category": "read-only"}
    if tool == "git" and action in {"rev-parse", "remote"}:
        return {"risk": "low", "reason": "safe git read", "category": "read-only"}
    if tool == "git" and action == "push" and intent.get("force"):
        return {"risk": "high", "reason": "force push", "category": "mutating"}
    if tool == "git" and action == "push":
        return {"risk": "medium", "reason": "git push", "category": "mutating"}
    if tool == "sed":
        flags = set(intent.get("flags", []))
        if "n" in flags and "i" not in flags and "in-place" not in flags:
            return {"risk": "low", "reason": "read-only stream edit", "category": "read-only"}
    if tool == "sort":
        flags = set(intent.get("flags", []))
        if "o" not in flags and "output" not in flags:
            return {"risk": "low", "reason": "read-only sort", "category": "read-only"}
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
        response = self.server.broker.handle(request, self.wfile)
        if response is not None:
            self.wfile.write((json.dumps(response) + "\n").encode("utf-8"))
            self.wfile.flush()


class BrokerServer:
    def __init__(
        self,
        path,
        policy_store,
        capabilities=None,
        delegates=None,
        event_sink=None,
        log_stderr=False,
        llm_policy=None,
        jit_engine=None,
    ):
        self.path = path
        self.policy_store = policy_store
        self.capabilities = capabilities or {}
        self.delegates = {item["name"]: item for item in (delegates or []) if item.get("name")}
        self.server = None
        self.event_sink = event_sink
        self.log_stderr = log_stderr
        self.jit_engine = jit_engine or JITRuleEngine(llm_policy or {})

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

    def _write_frame(self, wfile, payload):
        wfile.write((json.dumps(payload) + "\n").encode("utf-8"))
        wfile.flush()

    def handle(self, request, wfile=None):
        req_type = request.get("type")
        if req_type == "capability":
            return self._handle_capability(request, wfile)
        if req_type != "exec":
            return {"decision": "deny", "reason": "unsupported request"}
        argv = request["argv"]
        intent = normalize(argv)
        matched = self.policy_store.match(intent)
        raw = request.get("raw") or shlex.join(argv)
        context = {"cwd": request.get("cwd")}
        if matched:
            decision = "allow" if matched["allow"] else "deny"
            self._log(
                decision.upper(),
                raw,
                "policy",
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=event_template(intent, {"category": "policy"}),
                risk="policy",
                reason="matched policy",
            )
            return {"decision": decision, "reason": "matched policy"}
        verdict = classify(intent, argv, delegates=self.delegates.values(), context=context)
        risk = verdict["risk"]
        if risk == "critical" or verdict.get("category") in SENSITIVE_DENY_CATEGORIES:
            self._log(
                "DENY",
                raw,
                verdict.get("category"),
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=event_template(intent, verdict),
                risk=risk,
                reason=verdict.get("reason"),
            )
            return {"decision": "deny", "reason": verdict["reason"]}
        delegated_tools = _delegate_tool_map(self.delegates.values())
        if intent["tool"] in delegated_tools or intent["tool"] in BROWSER_TOOLS:
            self._log(
                "DENY",
                raw,
                verdict.get("category"),
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=event_template(intent, verdict),
                risk=risk,
                reason=verdict.get("reason"),
            )
            return {"decision": "deny", "reason": verdict["reason"]}
        template = event_template(intent, verdict)
        if self.jit_engine.eligible(verdict):
            jit = self.jit_engine.decide(intent, raw, verdict, template, context=context)
            jit_config = getattr(self.jit_engine, "config", {}) or {}
            if (
                jit.get("decision_hint") == "allow"
                and jit.get("rule")
                and jit_config.get("jit_auto_apply_low_risk", True)
            ):
                self.policy_store.add_rule(jit["rule"])
                self._log(
                    "ALLOW",
                    raw,
                    verdict.get("category"),
                    kind="exec",
                    tool=intent["tool"],
                    verb=intent["action"],
                    template=template,
                    risk="jit",
                    reason=jit.get("reason"),
                    jit=True,
                    confidence=jit.get("confidence"),
                )
                return {"decision": "allow", "reason": f"jit-approved: {jit.get('reason', 'low-risk generalized rule')}"}
            if jit.get("decision_hint") == "allow" and jit.get("rule"):
                self._log(
                    "ASK",
                    raw,
                    verdict.get("category"),
                    kind="exec",
                    tool=intent["tool"],
                    verb=intent["action"],
                    template=template,
                    risk="jit",
                    reason="jit auto-apply disabled",
                    jit=True,
                    confidence=jit.get("confidence"),
                )
                return {"decision": "deny", "reason": "jit-review-required: auto-apply disabled"}
            if jit.get("decision_hint") == "reject":
                self._log(
                    "DENY",
                    raw,
                    verdict.get("category"),
                    kind="exec",
                    tool=intent["tool"],
                    verb=intent["action"],
                    template=template,
                    risk="jit",
                    reason=jit.get("reason"),
                    jit=True,
                    confidence=jit.get("confidence"),
                )
                return {"decision": "deny", "reason": f"jit-rejected: {jit.get('reason', 'unsafe command pattern')}"}
            self._log(
                "ASK",
                raw,
                verdict.get("category"),
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=template,
                risk="jit",
                reason=jit.get("reason"),
                jit=True,
                confidence=jit.get("confidence"),
            )
            return {"decision": "deny", "reason": f"jit-review-required: {jit.get('reason', 'unknown low-impact command')}"}
        if risk == "high":
            self.policy_store.learn(intent)
            self._log(
                "ASK",
                raw,
                verdict.get("category"),
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=template,
                risk=risk,
                reason=verdict.get("reason"),
            )
            return {"decision": "allow", "reason": f"auto-approved: {verdict['reason']}"}
        if risk == "medium":
            self.policy_store.learn(intent)
        self._log(
            "ALLOW",
            raw,
            verdict.get("category"),
            kind="exec",
            tool=intent["tool"],
            verb=intent["action"],
            template=template,
            risk=risk,
            reason=verdict.get("reason"),
        )
        return {"decision": "allow", "reason": verdict["reason"]}

    def _handle_capability(self, request, wfile=None):
        name = request.get("name")
        matched = self.policy_store.match({"name": name}, kind="capability")
        allowed = bool(self.capabilities.get(name))
        if name == "delegate":
            delegate_name = request.get("payload", {}).get("name")
            allowed = bool(delegate_name) and delegate_name in set(self.capabilities.get("delegates", []))
        if matched is not None:
            allowed = allowed and matched["allow"]
        if not allowed:
            self._log("DENY", f"capability {name}", "capability", kind="capability", capability=name)
            return {"decision": "deny", "reason": f"{name} capability denied"}
        if name == "delegate":
            payload = request.get("payload", {})
            delegate_name = payload.get("name", "")
            delegate = self.delegates.get(delegate_name)
            if delegate and delegate.get("mode") == "execute" and wfile is not None:
                self._log("ALLOW", f"capability {name}", "capability")
                self._write_frame(wfile, {"decision": "allow", "reason": "capability allowed", "stream": True})
                stream_delegate_proxy(
                    self.capabilities,
                    self.delegates,
                    delegate_name,
                    payload.get("command", []),
                    lambda frame: self._write_frame(wfile, frame),
                )
                return None
            result = run_delegate_proxy(self.capabilities, self.delegates, delegate_name, payload.get("command", []))
        elif name == "browser_automation":
            result = run_browser_proxy(self.capabilities, request.get("payload", {}))
        elif name == "skills_proxy":
            result = run_skill_proxy(self.capabilities, request.get("payload", {}))
        else:
            result = {"status": "ok", "name": name}
        self._log("ALLOW", f"capability {name}", "capability", kind="capability", capability=name)
        return {"decision": "allow", "reason": "capability allowed", "result": result}

    def _log(self, tag, raw, category=None, **extra):
        event = {"action": tag.lower(), "category": category, "raw": raw}
        event.update({key: value for key, value in extra.items() if value is not None})
        if self.event_sink:
            self.event_sink.emit(event)
        if self.log_stderr:
            print(render_event(event), file=sys.stderr, flush=True)


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


def broker_exchange(sock_path, payload):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(sock_path)
        client.sendall((json.dumps(payload) + "\n").encode("utf-8"))
        buffer = b""
        while True:
            while b"\n" not in buffer:
                chunk = client.recv(65536)
                if not chunk:
                    if buffer:
                        yield json.loads(buffer.decode("utf-8"))
                    return
                buffer += chunk
            line, buffer = buffer.split(b"\n", 1)
            if not line:
                continue
            yield json.loads(line.decode("utf-8"))
