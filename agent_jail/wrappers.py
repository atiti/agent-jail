import os
import sys
import time
import json

from agent_jail.broker import broker_request

BLACKLISTED_WRAPPERS = {"agent-jail", "agent-jail-cap"}


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
    if session_proxy_env:
        # Allow the parent agent to stay unproxied while wrapped subprocesses
        # inherit the session-managed proxy/cert environment.
        for key in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "SOCKS_PROXY", "SSL_CERT_FILE", "SSL_CERT_DIR"):
            os.environ.pop(key, None)
        os.environ.update(json.loads(session_proxy_env))
    exec_argv = reply.get("rewrite") or full_argv
    os.execv(real_binary, exec_argv)
