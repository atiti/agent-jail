import os
import subprocess
import threading


def _expand_delegate_env_value(value, env):
    if not isinstance(value, str):
        return value
    previous_home = os.environ.get("HOME")
    try:
        if env.get("HOME"):
            os.environ["HOME"] = env["HOME"]
        return os.path.expandvars(os.path.expanduser(value))
    finally:
        if previous_home is None:
            os.environ.pop("HOME", None)
        else:
            os.environ["HOME"] = previous_home


def _delegate_env(delegate):
    env = os.environ.copy()
    host_home = env.get("AGENT_JAIL_HOST_HOME")
    if host_home:
        env["HOME"] = host_home
    original_path = env.get("AGENT_JAIL_ORIG_PATH")
    if original_path:
        env["PATH"] = original_path
    for key in list(env):
        if key.startswith("AGENT_JAIL_") and key not in {"AGENT_JAIL_HOST_HOME", "AGENT_JAIL_ORIG_PATH"}:
            env.pop(key, None)
    for key, value in (delegate.get("set_env") or {}).items():
        if isinstance(key, str) and key:
            env[key] = _expand_delegate_env_value(value, env)
    return env


def _delegate_command_argv(delegate, command):
    argv = list(command)
    if delegate.get("strip_tool_name") and argv:
        argv = argv[1:]
    return argv


def _build_delegate_command(delegate, command):
    argv = _delegate_command_argv(delegate, command)
    executor = delegate.get("executor")
    if executor:
        argv = [executor, *argv]
    run_as_user = delegate.get("run_as_user")
    if run_as_user:
        argv = ["sudo", "-n", "-u", run_as_user, *argv]
    return argv


def run_delegate_proxy(capabilities, delegates, name, command):
    allowed = set(capabilities.get("delegates", []))
    if name not in allowed:
        raise PermissionError(f"delegate {name} capability denied")
    delegate = delegates.get(name)
    if not delegate:
        return {"status": "ok", "delegate": name, "command": list(command)}
    allowed_tools = set(delegate.get("allowed_tools", []))
    if allowed_tools:
        tool = command[0] if command else ""
        if tool not in allowed_tools:
            raise PermissionError(f"delegate {name} does not allow tool {tool}")
    delegated = _build_delegate_command(delegate, command)
    env = _delegate_env(delegate)
    if delegate.get("mode") == "execute":
        proc = subprocess.run(delegated, text=True, capture_output=True, env=env)
        return {
            "status": "ok" if proc.returncode == 0 else "error",
            "delegate": name,
            "command": list(command),
            "delegated_command": delegated,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
    return {"status": "ok", "delegate": name, "command": list(command), "delegated_command": delegated}


def stream_delegate_proxy(capabilities, delegates, name, command, write_frame):
    allowed = set(capabilities.get("delegates", []))
    if name not in allowed:
        raise PermissionError(f"delegate {name} capability denied")
    delegate = delegates.get(name)
    if not delegate:
        raise PermissionError(f"delegate {name} is not configured")
    allowed_tools = set(delegate.get("allowed_tools", []))
    if allowed_tools:
        tool = command[0] if command else ""
        if tool not in allowed_tools:
            raise PermissionError(f"delegate {name} does not allow tool {tool}")
    delegated = _build_delegate_command(delegate, command)
    env = _delegate_env(delegate)
    header = f"[delegate:{name}] {' '.join(delegated)}\n"
    write_frame({"type": "header", "stream": "stderr", "text": header})
    proc = subprocess.Popen(
        delegated,
        text=True,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        bufsize=1,
    )

    def pump(pipe, stream_name):
        try:
            while True:
                chunk = pipe.readline()
                if not chunk:
                    break
                write_frame({"type": "data", "stream": stream_name, "text": chunk})
        finally:
            pipe.close()

    threads = [
        threading.Thread(target=pump, args=(proc.stdout, "stdout"), daemon=True),
        threading.Thread(target=pump, args=(proc.stderr, "stderr"), daemon=True),
    ]
    for thread in threads:
        thread.start()
    returncode = proc.wait()
    for thread in threads:
        thread.join()
    write_frame({"type": "exit", "returncode": returncode})
