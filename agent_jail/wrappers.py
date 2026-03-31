import os
import sys
import time

from agent_jail.broker import broker_request

BLACKLISTED_WRAPPERS = {"python", "python3", "node", "agent-jail", "agent-jail-cap"}


DISPATCHER = """#!/bin/sh
exec "{python}" -c 'from agent_jail.wrappers import dispatch_main; dispatch_main()' "$0" "$@"
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
    dispatcher = os.path.join(wrapper_dir, "_agent_jail_dispatch")
    python_executable = python_executable or sys.executable
    with open(dispatcher, "w", encoding="utf-8") as handle:
        handle.write(DISPATCHER.format(python=python_executable))
    os.chmod(dispatcher, 0o755)
    if commands is None:
        commands = visible_commands(source_path or os.environ.get("PATH", ""))
    for name in commands:
        if name == "_agent_jail_dispatch" or name in BLACKLISTED_WRAPPERS:
            continue
        target = os.path.join(wrapper_dir, name)
        if os.path.lexists(target):
            os.unlink(target)
        try:
            os.symlink("_agent_jail_dispatch", target)
        except OSError:
            with open(target, "w", encoding="utf-8") as handle:
                handle.write(DISPATCHER.format(python=python_executable))
            os.chmod(target, 0o755)


def resolve_real_binary(command):
    for directory in os.environ.get("AGENT_JAIL_ORIG_PATH", "").split(os.pathsep):
        candidate = os.path.join(directory, command)
        if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate
    raise FileNotFoundError(command)


def dispatch_main():
    argv = sys.argv[1:]
    command = os.path.basename(argv[0]) if argv else ""
    full_argv = [command, *argv[1:]]
    sock = os.environ["AGENT_JAIL_SOCKET"]
    payload = {"type": "exec", "argv": full_argv, "raw": " ".join(full_argv)}
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
    exec_argv = reply.get("rewrite") or full_argv
    os.execv(real_binary, exec_argv)
