import os
import sys
import time
import json

from agent_jail.broker import broker_request

BLACKLISTED_WRAPPERS = {"agent-jail", "agent-jail-cap"}
PROXY_RESTORE_WRAPPERS = {"sh", "bash", "zsh"}


WRAPPER_TEMPLATE = """#!/bin/sh
export AGENT_JAIL_INVOKED_AS="{command}"
exec "{python}" -c 'from agent_jail.wrappers import dispatch_main; dispatch_main()' "$@"
"""


def visible_commands(path_string):
    seen = set()
    for directory in path_string.split(os.pathsep):
        if not directory or not os.path.isdir(directory):
            continue
        for name in os.listdir(directory):
            candidate = os.path.join(directory, name)
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                seen.add(name)
    return sorted(seen)


def write_wrappers(wrapper_dir, commands=None, source_path=None, python_executable=None):
    os.makedirs(wrapper_dir, exist_ok=True)
    python_executable = python_executable or sys.executable
    if commands is None:
        commands = visible_commands(source_path or os.environ.get("PATH", ""))
    for name in commands:
        if name in BLACKLISTED_WRAPPERS:
            continue
        target = os.path.join(wrapper_dir, name)
        if os.path.lexists(target):
            os.unlink(target)
        with open(target, "w", encoding="utf-8") as handle:
            handle.write(WRAPPER_TEMPLATE.format(python=python_executable, command=name))
        os.chmod(target, 0o755)
    python_shim = os.path.join(wrapper_dir, "python")
    if not os.path.lexists(python_shim):
        os.symlink(python_executable, python_shim)


def resolve_real_binary(command):
    for directory in os.environ.get("AGENT_JAIL_ORIG_PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(command)


def dispatch_main():
    argv = sys.argv[1:]
    command = os.environ.get("AGENT_JAIL_INVOKED_AS", "")
    full_argv = [command, *argv]
    sock = os.environ["AGENT_JAIL_SOCKET"]
    payload = {"type": "exec", "argv": full_argv, "raw": " ".join(full_argv), "cwd": os.getcwd()}
    for _ in range(20):
        try:
            reply = broker_request(sock, payload)
            break
        except OSError:
            time.sleep(0.05)
    else:
        print("agent-jail: broker unavailable", file=sys.stderr)
        raise SystemExit(125)
    if reply["decision"] == "deny":
        print(f"agent-jail denied: {reply['reason']}", file=sys.stderr)
        raise SystemExit(126)
    real_binary = resolve_real_binary(command)
    session_proxy_env = os.environ.get("AGENT_JAIL_SESSION_PROXY_ENV")
    session_dir = os.environ.get("AGENT_JAIL_SESSION_DIR", "")
    session_proxy_env_file = os.path.join(session_dir, "session-proxy-env.json") if session_dir else ""
    if not session_proxy_env and session_proxy_env_file:
        try:
            with open(session_proxy_env_file, "r", encoding="utf-8") as handle:
                session_proxy_env = handle.read()
        except OSError:
            session_proxy_env = None
    bypass_hops = int(os.environ.get("AGENT_JAIL_PROXY_BYPASS_WRAPPER_HOPS", "0") or "0")
    if bypass_hops > 0:
        os.environ["AGENT_JAIL_PROXY_BYPASS_WRAPPER_HOPS"] = str(bypass_hops - 1)
    elif session_proxy_env and command in PROXY_RESTORE_WRAPPERS:
        # In commands-only mode, restore proxy env only for shell-based user
        # command execution, not arbitrary internal subprocesses like MCP
        # workers or agent bootstrap helpers.
        for key in (
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "SOCKS_PROXY",
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "socks_proxy",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
        ):
            os.environ.pop(key, None)
        os.environ.update(json.loads(session_proxy_env))
    exec_argv = reply.get("rewrite") or full_argv
    os.execv(real_binary, exec_argv)
