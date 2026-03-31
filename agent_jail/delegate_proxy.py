import subprocess


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
    if delegate.get("mode") == "execute":
        proc = subprocess.run(delegated, text=True, capture_output=True)
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
