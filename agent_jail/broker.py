import json
import fnmatch
import os
import shlex
import socket
import sys
import threading
import time
from socketserver import StreamRequestHandler, ThreadingUnixStreamServer

from agent_jail.browser_proxy import run_browser_proxy
from agent_jail.delegate_proxy import delegate_matches_command, format_delegate_display, prepare_delegate_proxy, run_delegate_proxy, stream_delegate_proxy
from agent_jail.events import render_event
from agent_jail.rule_jit import JITRuleEngine
from agent_jail.script_analysis import analyze_invocation, detect_secret_capabilities
from agent_jail.shell_analysis import ShellAnalysisError, analyze_shell_script
from agent_jail.skills_proxy import run_skill_proxy

BROWSER_TOOLS = {"peekaboo", "playwright-cli", "screencog"}
AGENT_TOOLS = {"codex", "claude"}
AGENT_LAUNCH_BYPASS_FLAGS = {
    "--dangerously-bypass-approvals-and-sandbox",
    "--allow-dangerously-skip-permissions",
}
AGENT_SCRIPT_MARKERS = (
    "/@openai/codex/",
    "/@anthropic-ai/claude-code/",
)
AGENT_KEYCHAIN_SERVICES = {
    "Claude Code",
    "Claude Code-credentials",
}
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
    "secret-capability",
}
SAFE_CLEANUP_NAMES = {
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    ".hypothesis",
    ".tox",
}
READ_PATH_TOOLS = {"cat", "head", "ls", "find", "grep", "rg", "sed", "sort", "tail"}
CAPABILITY_BRIDGE_MODULE = "agent_jail.cap_cli"
FLAG_VALUE_COUNTS = {
    "find": {"maxdepth": 1, "mindepth": 1, "type": 1, "name": 1, "path": 1},
    "grep": {"e": 1, "f": 1, "m": 1},
    "head": {"n": 1, "c": 1},
    "ls": {"d": 0},
    "rg": {"e": 1, "g": 1, "m": 1},
    "sort": {"o": 1, "t": 1, "k": 1},
    "tail": {"n": 1, "c": 1},
}
GIT_FLAGS_WITH_VALUES = {
    "-C",
    "-c",
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--config-env",
    "--exec-path",
}
SSH_FLAGS_WITH_VALUES = {
    "-b",
    "-c",
    "-D",
    "-E",
    "-e",
    "-F",
    "-I",
    "-i",
    "-J",
    "-L",
    "-l",
    "-m",
    "-O",
    "-o",
    "-p",
    "-Q",
    "-R",
    "-S",
    "-W",
    "-w",
}


def event_template(intent, verdict=None):
    if intent.get("template"):
        return intent["template"]
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


def _jit_review_is_actionable(jit):
    if jit.get("decision_hint") != "ask":
        return False
    confidence = jit.get("confidence")
    try:
        if confidence is not None and float(confidence) == 0.0:
            return False
    except (TypeError, ValueError):
        pass
    reason = (jit.get("reason") or "").lower()
    if reason.startswith("jit provider unavailable:"):
        return False
    if reason.startswith("jit http error:"):
        return False
    if reason.startswith("jit request failed:"):
        return False
    if reason in {"jit response payload was not valid json", "jit response was not valid json"}:
        return False
    return True


def _with_delegate_context(delegate, payload=None):
    item = dict(delegate or {})
    if payload and payload.get("cwd"):
        item["_cwd"] = payload.get("cwd")
    return item


def normalize(argv):
    tool = os.path.basename(argv[0]) if argv else ""
    flags = []
    action = "exec"
    target = None
    force = False
    if tool in {"sh", "bash", "zsh"} and len(argv) > 2 and argv[1] in {"-c", "-lc"}:
        action = "command-string"
        flags.append(argv[1].lstrip("-"))
        target = argv[2]
    elif tool == "git":
        action = ""
        skip_value = False
        for item in argv[1:]:
            if skip_value:
                skip_value = False
                continue
            if item.startswith("-"):
                flag = item.lstrip("-")
                flags.append(flag)
                if flag in {"f", "force"}:
                    force = True
                if item in GIT_FLAGS_WITH_VALUES or any(item.startswith(prefix + "=") for prefix in GIT_FLAGS_WITH_VALUES):
                    if "=" not in item:
                        skip_value = True
            elif not action:
                action = item
            elif target is None:
                target = item
            elif action == "push":
                target = f"{target}/{item}"
    else:
        for item in argv[1:]:
            if item.startswith("-"):
                flag = item.lstrip("-")
                flags.append(flag)
                if flag in {"f", "force"}:
                    force = True
            elif target is None:
                target = item
    return {"tool": tool, "action": action or "exec", "target": target, "flags": flags, "force": force}


def _is_agent_tool(tool):
    base = os.path.basename(tool or "")
    stem = base.split(".", 1)[0]
    return base in AGENT_TOOLS or stem in AGENT_TOOLS


def _is_agent_launcher_argv(argv):
    if not argv:
        return False
    tool = os.path.basename(argv[0])
    if _is_agent_tool(tool):
        return True
    if tool not in {"node", "nodejs"}:
        return False
    for item in argv[1:]:
        if item.startswith("-"):
            continue
        normalized = item.replace("\\", "/").lower()
        if any(marker in normalized for marker in AGENT_SCRIPT_MARKERS):
            return True
        base = os.path.basename(item)
        stem = base.split(".", 1)[0]
        if stem in AGENT_TOOLS:
            return True
    return False


def _is_agent_keychain_lookup_argv(argv):
    if not argv or os.path.basename(argv[0]) != "security":
        return False
    if len(argv) < 2 or argv[1] != "find-generic-password":
        return False
    service = None
    wants_secret = False
    pending_flag = None
    for item in argv[2:]:
        if pending_flag is not None:
            if pending_flag == "-s":
                service = item
            pending_flag = None
            continue
        if item == "-w":
            wants_secret = True
            continue
        if item in {"-a", "-s"}:
            pending_flag = item
    return wants_secret and service in AGENT_KEYCHAIN_SERVICES


def _is_python_tool(tool):
    base = os.path.basename(tool or "")
    return base == "python" or base.startswith("python")


def _is_internal_cap_bridge_argv(argv):
    if not argv:
        return False
    tool = os.path.basename(argv[0])
    if tool == "agent-jail-cap":
        return True
    if not _is_python_tool(tool):
        return False
    if len(argv) >= 3 and argv[1] == "-m" and argv[2] == CAPABILITY_BRIDGE_MODULE:
        return True
    if len(argv) >= 3 and argv[1] == "-":
        script_target = argv[2]
        if os.path.basename(script_target) == "agent-jail-cap" and ".agent-jail" in script_target:
            return True
    return False


def _is_safe_ati_cto_brief_argv(argv):
    if not argv or not _is_python_tool(argv[0]):
        return False
    script_path = None
    index = 1
    while index < len(argv):
        item = argv[index]
        if item in {"-m", "-c", "-"}:
            return False
        if item.startswith("-"):
            index += 1
            continue
        script_path = item
        index += 1
        break
    if not script_path:
        return False
    normalized = os.path.realpath(os.path.abspath(os.path.expanduser(script_path)))
    if not normalized.endswith(os.path.join("skills", "ati-cto", "scripts", "ati_cto_brief.py")):
        return False
    allowed_flags = {"--local-only", "--scope"}
    while index < len(argv):
        item = argv[index]
        if item == "--local-only":
            index += 1
            continue
        if item == "--scope":
            if index + 1 >= len(argv):
                return False
            index += 2
            continue
        if item.startswith("-"):
            return False
        return False
    return True


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


def _command_path_args(argv):
    if not argv:
        return []
    tool = os.path.basename(argv[0])
    items = argv[1:]
    if tool == "cat":
        return [item for item in items if not item.startswith("-")]
    if tool in {"head", "tail", "sort", "ls"}:
        return _non_flag_paths(tool, items)
    if tool == "sed":
        parts = [item for item in items if not item.startswith("-")]
        return parts[1:] if len(parts) > 1 else []
    if tool in {"grep", "rg"}:
        parts = _non_flag_parts(tool, items)
        if "--files" in items:
            return parts
        return parts[1:] if len(parts) > 1 else []
    if tool == "find":
        paths = []
        for item in items:
            if item in {"(", ")", "!", "-o", "-and", "-or"}:
                break
            if item.startswith("-"):
                break
            paths.append(item)
        return paths or ["."]
    return []


def _non_flag_parts(tool, items):
    result = []
    skip = 0
    value_flags = FLAG_VALUE_COUNTS.get(tool, {})
    index = 0
    while index < len(items):
        item = items[index]
        if skip:
            skip -= 1
            index += 1
            continue
        if item == "--":
            result.extend(items[index + 1 :])
            break
        if item.startswith("--"):
            name = item[2:]
            if "=" in name:
                name = name.split("=", 1)[0]
            skip = value_flags.get(name, 0)
            index += 1
            continue
        if item.startswith("-") and item != "-" and item not in {"-"}:
            name = item.lstrip("-")
            skip = value_flags.get(name, 0)
            index += 1
            continue
        result.append(item)
        index += 1
    return result


def _non_flag_paths(tool, items):
    parts = _non_flag_parts(tool, items)
    return [item for item in parts if not item.isdigit()]


def _allowed_read_roots(context):
    roots = [os.path.realpath(os.path.abspath(path)) for path in (context or {}).get("read_roots", []) if path]
    cwd = (context or {}).get("cwd")
    if cwd:
        roots.append(os.path.realpath(os.path.abspath(cwd)))
    deduped = []
    for path in roots:
        if path not in deduped:
            deduped.append(path)
    return deduped


def _matches_deny_pattern(candidate, patterns):
    expanded = os.path.abspath(os.path.expanduser(candidate))
    for pattern in patterns or ():
        normalized = os.path.abspath(os.path.expanduser(pattern))
        if fnmatch.fnmatch(expanded, normalized):
            return normalized
    return None


def _path_within_roots(path, cwd, roots):
    candidate = os.path.realpath(os.path.abspath(path if os.path.isabs(path) else os.path.join(cwd or os.getcwd(), path)))
    for root in roots:
        try:
            if os.path.commonpath([candidate, root]) == root:
                return candidate
        except ValueError:
            continue
    return None


def _read_scope_violation(intent, argv, context, analysis=None):
    roots = _allowed_read_roots(context)
    if not roots:
        return None
    deny_patterns = (context or {}).get("deny_read_patterns", [])
    cwd = (context or {}).get("cwd")
    commands = []
    paths = []
    if analysis:
        commands.extend(analysis.get("commands", []))
        paths.extend(analysis.get("read_paths", []))
    if intent.get("tool") in READ_PATH_TOOLS:
        paths.extend(_command_path_args(argv))
    for path in paths:
        matched = _matches_deny_pattern(path if os.path.isabs(path) else os.path.join(cwd or os.getcwd(), path), deny_patterns)
        if matched:
            return {
                "risk": "critical",
                "reason": f"read path is blocked by policy: {path}",
                "category": "read-scope",
            }
        if not _path_within_roots(path, cwd, roots):
            return {
                "risk": "critical",
                "reason": f"read path is outside allowed roots: {path}",
                "category": "read-scope",
            }
    for command in commands:
        nested_intent = normalize(command)
        nested = _read_scope_violation(nested_intent, command, context, analysis=None)
        if nested:
            return nested
    return None


def _secret_env_capability_violation(argv, context, analysis, delegates, secrets):
    env_vars = (analysis or {}).get("secret_env_vars", [])
    if env_vars:
        capabilities = []
        for name, item in (secrets or {}).items():
            env_map = item.get("env") if isinstance(item, dict) else {}
            if any(env_name in env_map for env_name in env_vars):
                capabilities.append(name)
        detected = {"secret_capabilities": sorted(set(capabilities))}
    else:
        detected = detect_secret_capabilities(argv, (context or {}).get("cwd"), secrets or {})
    capabilities = detected.get("secret_capabilities", [])
    if not capabilities:
        return None
    script_path = None
    if analysis and analysis.get("source_path") and argv and argv[0] == analysis.get("source_path"):
        script_path = os.path.abspath(analysis["source_path"])
    elif argv and os.path.sep in argv[0]:
        candidate = os.path.abspath(os.path.join((context or {}).get("cwd") or os.getcwd(), argv[0]))
        if os.path.isfile(candidate):
            script_path = candidate
    preferred = []
    fallback = []
    for delegate in delegates or ():
        allowed = set(delegate.get("allowed_secrets") or [])
        if allowed and set(capabilities).issubset(allowed):
            if delegate_matches_command(delegate, argv):
                preferred.append(delegate)
            else:
                fallback.append(delegate)
    chosen = (preferred or fallback or [None])[0]
    if not preferred and script_path:
        capability = capabilities[0]
        delegate_name = _derive_local_secret_delegate_name(script_path, capability)
        return {
            "risk": "high",
            "reason": (
                f"secret capability required: {', '.join(capabilities)}; "
                f"approve an exact-path delegate for {script_path}"
            ),
            "category": "secret-capability",
            "review_kind": "delegate-config",
            "script_path": script_path,
            "secret_capability": capability,
            "delegate": {
                "name": delegate_name,
                "allowed_tools": [script_path],
                "allowed_secrets": [capability],
                "mode": "execute",
            },
        }
    if chosen:
        names = ", ".join(capabilities)
        rerun = _secret_delegate_rerun_command(chosen.get("name"), argv, analysis, script_path)
        return {
            "risk": "high",
            "reason": f"secret capability required: {names}; rerun: {rerun}",
            "category": "secret-capability",
        }
    names = ", ".join(capabilities)
    return {
        "risk": "critical",
        "reason": f"secret capability required but no configured delegate can provide it: {names}",
        "category": "secret-capability",
    }


def _sanitize_delegate_name_part(value):
    cleaned = []
    for char in value.lower():
        if char.isalnum():
            cleaned.append(char)
        else:
            cleaned.append("-")
    text = "".join(cleaned).strip("-")
    while "--" in text:
        text = text.replace("--", "-")
    return text or "script"


def _derive_local_secret_delegate_name(script_path, capability):
    script_name = _sanitize_delegate_name_part(os.path.basename(script_path))
    capability_name = _sanitize_delegate_name_part(capability)
    return f"local-secret-{script_name}-{capability_name}"


def _secret_delegate_rerun_argv(delegate_name, argv, analysis=None, script_path=None):
    command = list(argv or [])
    source_path = script_path or ((analysis or {}).get("source_path") if analysis else None)
    if source_path and command:
        tool = os.path.basename(command[0])
        if tool in {"sh", "bash", "zsh"} and source_path in command[1:]:
            source_index = command.index(source_path)
            command = [source_path, *command[source_index + 1 :]]
    return ["agent-jail-cap", "delegate", delegate_name, *command]


def _secret_delegate_rerun_command(delegate_name, argv, analysis=None, script_path=None):
    return shlex.join(_secret_delegate_rerun_argv(delegate_name, argv, analysis=analysis, script_path=script_path))


def _configured_git_ssh_hosts(context):
    values = []
    for item in (context or {}).get("git_ssh_hosts", []):
        if not isinstance(item, str):
            continue
        value = item.strip().lower()
        if not value:
            continue
        if value not in values:
            values.append(value)
    return values


def _normalize_ssh_host(host):
    if not isinstance(host, str):
        return ""
    value = host.strip().lower()
    if not value:
        return ""
    if "@" in value:
        value = value.rsplit("@", 1)[-1]
    if value.startswith("[") and "]" in value:
        value = value[1:].split("]", 1)[0]
    elif ":" in value:
        value = value.split(":", 1)[0]
    return value


def _extract_ssh_destination_and_remote_command(argv):
    destination = None
    remote_command = None
    index = 1
    while index < len(argv):
        item = argv[index]
        if item == "--":
            index += 1
            break
        if item in SSH_FLAGS_WITH_VALUES:
            index += 2
            continue
        if item.startswith("-") and len(item) > 2 and item[:2] in SSH_FLAGS_WITH_VALUES:
            index += 1
            continue
        if item.startswith("-"):
            index += 1
            continue
        destination = item
        index += 1
        break
    if destination is None:
        return None, None
    if index < len(argv):
        remote_command = " ".join(argv[index:]).strip()
    return destination, remote_command


def _is_allowed_git_remote_command(remote_command):
    if not remote_command:
        return False
    text = remote_command.strip()
    if (text.startswith('"') and text.endswith('"')) or (text.startswith("'") and text.endswith("'")):
        text = text[1:-1].strip()
    return text.startswith(("git-receive-pack ", "git-upload-pack ", "git-upload-archive "))


def _classify_git_ssh_transport(argv, context):
    command_path = argv[0] if argv else ""
    if os.path.basename(command_path) != "ssh":
        return None
    hosts = set(_configured_git_ssh_hosts(context))
    if not hosts:
        return None
    destination, remote_command = _extract_ssh_destination_and_remote_command(argv)
    host = _normalize_ssh_host(destination)
    if host not in hosts:
        return None
    if not _is_allowed_git_remote_command(remote_command):
        return None
    return {
        "risk": "low",
        "reason": f"git ssh transport to configured host {host}",
        "category": "git-transport",
    }


def classify(intent, argv, delegates=None, context=None, secrets=None):
    raw = " ".join(argv)
    tool = intent["tool"]
    action = intent["action"]
    command_path = argv[0] if argv else ""
    git_ssh_verdict = _classify_git_ssh_transport(argv, context or {})
    if git_ssh_verdict is not None:
        return git_ssh_verdict
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
        secret_detection = detect_secret_capabilities(argv, (context or {}).get("cwd"), secrets or {})
        secret_verdict = _secret_env_capability_violation(
            argv,
            context or {},
            {"secret_env_vars": secret_detection.get("secret_env_vars", [])},
            delegates,
            secrets,
        )
        if secret_verdict is not None:
            return secret_verdict
        highest = None
        risk_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
        for command in analysis["commands"]:
            nested_intent = normalize(command)
            verdict = classify(nested_intent, command, delegates=delegates, context=context, secrets=secrets)
            if verdict["category"] in SENSITIVE_DENY_CATEGORIES:
                return verdict
            if highest is None or risk_rank[verdict["risk"]] > risk_rank[highest["risk"]]:
                highest = verdict
        if highest is not None:
            return highest
    secret_verdict = _secret_env_capability_violation(argv, context or {}, None, delegates, secrets)
    if secret_verdict is not None:
        return secret_verdict
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
    if _is_agent_keychain_lookup_argv(argv):
        return {
            "risk": "low",
            "reason": "agent auth keychain lookup under agent-jail outer control",
            "category": "agent-launch",
        }
    if _is_agent_launcher_argv(argv) and any(flag in argv[1:] for flag in AGENT_LAUNCH_BYPASS_FLAGS):
        return {
            "risk": "low",
            "reason": "agent launch under agent-jail outer control",
            "category": "agent-launch",
        }
    if _is_internal_cap_bridge_argv(argv):
        return {
            "risk": "low",
            "reason": "internal capability bridge under agent-jail control",
            "category": "capability-bridge",
        }
    if _is_safe_ati_cto_brief_argv(argv):
        return {
            "risk": "low",
            "reason": "local ati-cto brief generation script",
            "category": "read-only",
        }
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
        mounts=None,
        deny_read_patterns=None,
        event_sink=None,
        log_stderr=False,
        llm_policy=None,
        jit_engine=None,
        secrets=None,
        git_ssh_hosts=None,
        review_wait_timeout=300.0,
    ):
        self.path = path
        self.policy_store = policy_store
        self.capabilities = capabilities or {}
        self.delegates = {item["name"]: item for item in (delegates or []) if item.get("name")}
        self.mounts = mounts or []
        self.deny_read_patterns = deny_read_patterns or []
        self.server = None
        self.event_sink = event_sink
        self.log_stderr = log_stderr
        self.jit_engine = jit_engine or JITRuleEngine(llm_policy or {})
        self.secrets = secrets or {}
        self.git_ssh_hosts = list(git_ssh_hosts or [])
        self.review_wait_timeout = float(review_wait_timeout)

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

    def _wait_for_review_resolution(self, review_id, intent, raw, template):
        deadline = time.monotonic() + self.review_wait_timeout
        self._log(
            "ASK",
            raw,
            "review",
            kind="exec",
            tool=intent["tool"],
            verb=intent["action"],
            template=template,
            risk="jit",
            review_id=review_id,
            phase="wait",
            reason="waiting for manual review",
        )
        while time.monotonic() < deadline:
            self.policy_store.reload()
            matched = self.policy_store.match(intent)
            if matched and matched["allow"]:
                self._log(
                    "ALLOW",
                    raw,
                    "review",
                    kind="exec",
                    tool=intent["tool"],
                    verb=intent["action"],
                    template=template,
                    risk="jit",
                    review_id=review_id,
                    phase="approved",
                    reason="manual review approved",
                )
                return {"decision": "allow", "reason": f"review-approved[{review_id}]"}
            if self.policy_store.get_pending_review(review_id) is None:
                self._log(
                    "DENY",
                    raw,
                    "review",
                    kind="exec",
                    tool=intent["tool"],
                    verb=intent["action"],
                    template=template,
                    risk="jit",
                    review_id=review_id,
                    phase="rejected",
                    reason="manual review rejected",
                )
                return {"decision": "deny", "reason": f"jit-review-rejected[{review_id}]"}
            time.sleep(0.2)
        self._log(
            "ASK",
            raw,
            "review",
            kind="exec",
            tool=intent["tool"],
            verb=intent["action"],
            template=template,
            risk="jit",
            review_id=review_id,
            phase="timeout",
            reason=f"review wait timed out after {int(self.review_wait_timeout)}s",
        )
        return {"decision": "deny", "reason": f"jit-review-timeout[{review_id}]"}

    def handle(self, request, wfile=None):
        req_type = request.get("type")
        if req_type == "capability":
            return self._handle_capability(request, wfile)
        if req_type != "exec":
            return {"decision": "deny", "reason": "unsupported request"}
        argv = request["argv"]
        raw = request.get("raw") or shlex.join(argv)
        context = {
            "cwd": request.get("cwd"),
            "read_roots": [mount.get("path") for mount in self.mounts if mount.get("path")],
            "deny_read_patterns": list(self.deny_read_patterns),
            "git_ssh_hosts": list(self.git_ssh_hosts),
        }
        analysis = analyze_invocation(argv, context.get("cwd"))
        effective_argv = analysis.get("argv") or argv
        intent = normalize(effective_argv)
        if analysis.get("template"):
            intent["template"] = analysis["template"]
        read_guard = _read_scope_violation(intent, effective_argv, context, analysis=analysis)
        if read_guard:
            self._log(
                "DENY",
                raw,
                read_guard.get("category"),
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=event_template(intent, read_guard),
                risk=read_guard["risk"],
                reason=read_guard.get("reason"),
            )
            return {"decision": "deny", "reason": read_guard["reason"]}
        secret_guard = _secret_env_capability_violation(effective_argv, context, analysis, self.delegates.values(), self.secrets)
        if secret_guard:
            if secret_guard.get("review_kind") == "delegate-config":
                template = secret_guard.get("script_path") or event_template(intent, secret_guard)
                self._log(
                    "ASK",
                    raw,
                    secret_guard.get("category"),
                    kind="exec",
                    tool=os.path.basename(secret_guard.get("script_path") or intent["tool"]),
                    verb="secret-delegate",
                    template=template,
                    risk=secret_guard["risk"],
                    reason=secret_guard.get("reason"),
                    secret_capability=secret_guard.get("secret_capability"),
                )
                pending = self.policy_store.add_pending_review(
                    {
                        "kind": "delegate-config",
                        "tool": os.path.basename(secret_guard["script_path"]),
                        "action": "secret-delegate",
                        "raw": raw,
                        "template": template,
                        "reason": secret_guard.get("reason"),
                        "script_path": secret_guard["script_path"],
                        "secret_capability": secret_guard["secret_capability"],
                        "delegate": secret_guard["delegate"],
                    }
                )
                return {
                    "decision": "deny",
                    "reason": (
                        f"secret-delegate-review-required[{pending['id']}]: "
                        f"approve to add {pending['delegate']['name']} for {pending['script_path']}; "
                        f"rerun after approval: "
                        f"{_secret_delegate_rerun_command(pending['delegate']['name'], effective_argv, analysis=analysis, script_path=pending['script_path'])}"
                    ),
                }
            self._log(
                "DENY",
                raw,
                secret_guard.get("category"),
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=event_template(intent, secret_guard),
                risk=secret_guard["risk"],
                reason=secret_guard.get("reason"),
            )
            return {"decision": "deny", "reason": secret_guard["reason"]}
        matched = self.policy_store.match(intent)
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
        verdict = None
        if analysis.get("language") in {"python", "ruby", "perl"}:
            verdict = {
                "risk": analysis.get("risk", "low"),
                "reason": analysis.get("reason", "script analysis"),
                "category": analysis.get("category", "general"),
            }
        elif analysis.get("language") == "shell" and not (
            intent["tool"] in {"sh", "bash", "zsh"} and intent["action"] == "command-string"
        ):
            verdict = {
                "risk": analysis.get("risk", "low"),
                "reason": analysis.get("reason", "script analysis"),
                "category": analysis.get("category", "general"),
            }
        if verdict is None:
            verdict = classify(intent, effective_argv, delegates=self.delegates.values(), context=context, secrets=self.secrets)
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
        if self.jit_engine.should_attempt(verdict) and analysis.get("template") != "shell syntax check":
            self._log(
                "INFO",
                raw,
                "jit",
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=template,
                risk="jit",
                phase="start",
                reason="llm policy evaluation",
            )
            jit = self.jit_engine.decide(intent, raw, verdict, template, context=context)
            self._log(
                "INFO",
                raw,
                "jit",
                kind="exec",
                tool=intent["tool"],
                verb=intent["action"],
                template=template,
                risk="jit",
                phase="result",
                reason=jit.get("reason"),
                decision_hint=jit.get("decision_hint"),
                confidence=jit.get("confidence"),
                source=jit.get("source"),
                cached=jit.get("cached", False),
            )
            jit_config = getattr(self.jit_engine, "config", {}) or {}
            if (
                jit.get("decision_hint") == "allow"
                and jit.get("rule")
                and jit_config.get("jit_auto_apply_low_risk", True)
            ):
                if intent.get("template"):
                    constraints = dict((jit["rule"].get("constraints") or {}))
                    constraints.setdefault("template", intent["template"])
                    jit["rule"]["constraints"] = constraints
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
            if not _jit_review_is_actionable(jit):
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
                return {"decision": "deny", "reason": f"jit-unreviewable: {jit.get('reason', 'unable to evaluate command safely')}"}
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
            pending = self.policy_store.add_pending_review(
                {
                    "kind": "exec",
                    "tool": intent["tool"],
                    "action": intent["action"],
                    "raw": raw,
                    "template": ((jit.get("rule") or {}).get("metadata") or {}).get("template", template),
                    "reason": jit.get("reason", "unknown low-impact command"),
                    "confidence": jit.get("confidence"),
                    "source": jit.get("source"),
                    "decision_hint": jit.get("decision_hint"),
                    "rule": _review_rule_with_template(jit.get("rule"), intent.get("template")),
                }
            )
            return self._wait_for_review_resolution(pending["id"], intent, raw, template)
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
            delegate = _with_delegate_context(self.delegates.get(delegate_name), payload)
            if delegate:
                delegate["configured_secrets"] = self.secrets
            if delegate and delegate.get("mode") == "execute" and wfile is not None:
                try:
                    _, delegated, delegated_env = prepare_delegate_proxy(
                        self.capabilities,
                        {**self.delegates, delegate_name: delegate},
                        delegate_name,
                        payload.get("command", []),
                    )
                except PermissionError as exc:
                    self._log("DENY", f"capability {name}", "capability", kind="capability", capability=name, reason=str(exc))
                    return {"decision": "deny", "reason": str(exc)}
                delegated_raw = format_delegate_display(delegated, env=delegated_env)
                self._log(
                    "ALLOW",
                    delegated_raw,
                    "capability",
                    kind="capability",
                    capability=name,
                    delegate=delegate_name,
                    phase="start",
                )
                self._write_frame(wfile, {"decision": "allow", "reason": "capability allowed", "stream": True})
                _, returncode = stream_delegate_proxy(
                    self.capabilities,
                    {**self.delegates, delegate_name: delegate},
                    delegate_name,
                    payload.get("command", []),
                    lambda frame: self._write_frame(wfile, frame),
                )
                self._log(
                    "ALLOW" if returncode == 0 else "DENY",
                    delegated_raw,
                    "capability",
                    kind="capability",
                    capability=name,
                    delegate=delegate_name,
                    phase="exit",
                    reason=f"returncode={returncode}",
                )
                return None
            result = run_delegate_proxy(self.capabilities, {**self.delegates, delegate_name: delegate}, delegate_name, payload.get("command", []))
        elif name == "browser_automation":
            result = run_browser_proxy(self.capabilities, request.get("payload", {}))
        elif name == "skills_proxy":
            result = run_skill_proxy(self.capabilities, request.get("payload", {}))
        else:
            result = {"status": "ok", "name": name}
        self._log("ALLOW", f"capability {name}", "capability", kind="capability", capability=name)
        return {"decision": "allow", "reason": "capability allowed", "result": result}

    def _log(self, tag, raw, category=None, **extra):
        if (
            tag == "ALLOW"
            and extra.get("kind") == "capability"
            and extra.get("capability") == "delegate"
            and raw == "capability delegate"
        ):
            return
        if raw.startswith("dirname ") or raw.startswith("dirname -- "):
            if ".agent-jail/bin/agent-jail-cap" in raw:
                return
        event = {"action": tag.lower(), "category": category, "raw": raw}
        event.update({key: value for key, value in extra.items() if value is not None})
        if self.event_sink:
            self.event_sink.emit(event)
        if self.log_stderr:
            print(render_event(event), file=sys.stderr, flush=True)


def _review_rule_with_template(rule, template):
    if not rule or not template:
        return rule
    item = dict(rule)
    constraints = dict(item.get("constraints") or {})
    constraints.setdefault("template", template)
    item["constraints"] = constraints
    return item


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
