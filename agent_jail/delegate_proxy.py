import os
import re
import subprocess
import threading

from agent_jail.script_analysis import detect_secret_capabilities

SECRET_PLACEHOLDER = "***REDACTED***"
SECRET_NAME_RE = re.compile(r"(SECRET|TOKEN|PASSWORD|PASSWD|PASS|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|KEY)", re.IGNORECASE)
SECRET_ASSIGN_RE = re.compile(
    r"(\b(?:export\s+)?[A-Za-z_][A-Za-z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|PASS|API_KEY|ACCESS_KEY|PRIVATE_KEY|CLIENT_SECRET|KEY)[A-Za-z0-9_]*=)"
    r"(\"[^\"]*\"|'[^']*'|[^\s;|&]+)",
    re.IGNORECASE,
)
GENERIC_SECRET_ENTRYPOINTS = {"bash", "env", "perl", "python", "ruby", "sh", "zsh"}


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


def _inject_required_secret_env(env, delegate, command):
    allowed = set(delegate.get("allowed_secrets") or [])
    configured = delegate.get("configured_secrets") or {}
    if not allowed or not configured:
        return env
    detected = detect_secret_capabilities(command, delegate.get("_cwd"), configured)
    for capability in detected.get("secret_capabilities", []):
        if capability not in allowed:
            continue
        env_map = (configured.get(capability) or {}).get("env") or {}
        for key, value in env_map.items():
            env[key] = _expand_delegate_env_value(value, env)
    return env


def _looks_secret_key(name):
    return isinstance(name, str) and bool(SECRET_NAME_RE.search(name))


def _secret_replacements(env):
    values = []
    seen = set()
    for key, value in (env or {}).items():
        if not _looks_secret_key(key):
            continue
        if not isinstance(value, str) or not value:
            continue
        if value in seen:
            continue
        seen.add(value)
        values.append(value)
    values.sort(key=len, reverse=True)
    return values


def _redact_text(text, env=None):
    if not isinstance(text, str) or not text:
        return text
    redacted = text
    for value in _secret_replacements(env):
        redacted = redacted.replace(value, SECRET_PLACEHOLDER)
    redacted = SECRET_ASSIGN_RE.sub(r"\1" + SECRET_PLACEHOLDER, redacted)
    return redacted


def redact_argv(argv, env=None):
    return [_redact_text(item, env=env) for item in (argv or [])]


def format_delegate_display(argv, env=None, max_len=240):
    text = " ".join(redact_argv(argv, env=env))
    if max_len and len(text) > max_len:
        return text[: max_len - 3] + "..."
    return text


def _inventory_tool_names(delegate):
    configured = delegate.get("inventory_tools")
    if configured:
        return {os.path.basename(tool) for tool in configured if isinstance(tool, str) and tool}
    if delegate.get("auto_inventory_from_cwd") and delegate.get("strip_tool_name"):
        return {os.path.basename(tool) for tool in (delegate.get("allowed_tools") or []) if isinstance(tool, str) and tool}
    return set()


def _delegate_note(command):
    if not command:
        return None
    tool = os.path.basename(command[0])
    if len(command) > 1 and command[1] == "exec" and "--approve" not in command:
        return f"{tool} exec defaults to dry-run; add --approve to execute and --elevated when required"
    return None


def _is_generic_secret_entrypoint(tool):
    base = os.path.basename(tool or "")
    return base in GENERIC_SECRET_ENTRYPOINTS or base.startswith("python")


def _validate_delegate_command(delegate, command):
    if not command:
        raise PermissionError(f"delegate {delegate.get('name', 'unknown')} requires a command")
    tool = command[0]
    inventory_tools = _inventory_tool_names(delegate)
    if delegate.get("auto_inventory_from_cwd") and delegate.get("strip_tool_name") and inventory_tools and tool not in inventory_tools:
        expected = ", ".join(sorted(inventory_tools))
        raise PermissionError(
            f"delegate {delegate.get('name', 'unknown')} expects a control-plane tool entrypoint ({expected}), got {tool}"
        )
    allowed_tools = set(delegate.get("allowed_tools", []))
    if allowed_tools and tool not in allowed_tools:
        allowed_text = ", ".join(sorted(allowed_tools))
        raise PermissionError(
            f"delegate {delegate.get('name', 'unknown')} does not allow tool {tool}; allowed tools: {allowed_text}"
        )
    if (
        delegate.get("allowed_secrets")
        and not delegate.get("allow_secret_shell")
        and _is_generic_secret_entrypoint(tool)
    ):
        raise PermissionError(
            f"delegate {delegate.get('name', 'unknown')} does not allow generic shell/interpreter entrypoints when secrets are injected"
        )


def delegate_matches_command(delegate, command):
    if not command:
        return False
    tool = command[0]
    allowed_tools = set(delegate.get("allowed_tools") or [])
    if not allowed_tools:
        return True
    if tool in allowed_tools:
        return True
    base = os.path.basename(tool)
    return base in allowed_tools


def _delegate_command_argv(delegate, command):
    argv = list(command)
    cwd = delegate.get("_cwd")
    auto_inventory = bool(delegate.get("auto_inventory_from_cwd"))
    inventory_tools = _inventory_tool_names(delegate)
    if auto_inventory and command:
        tool = os.path.basename(command[0])
        inventory_dir = os.path.join(cwd or "", "inventory") if cwd else ""
        if tool in inventory_tools and cwd and os.path.isdir(inventory_dir):
            has_ops_root = "--ops-root" in argv
            has_inventory_dir = "--inventory-dir" in argv
            defaults = []
            if not has_ops_root:
                defaults.extend(["--ops-root", cwd])
            if not has_inventory_dir:
                defaults.extend(["--inventory-dir", inventory_dir])
            if defaults:
                if delegate.get("strip_tool_name") and argv:
                    argv = [argv[0], *defaults, *argv[1:]]
                else:
                    argv = [argv[0], *defaults, *argv[1:]]
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


def prepare_delegate_proxy(capabilities, delegates, name, command):
    allowed = set(capabilities.get("delegates", []))
    if name not in allowed:
        raise PermissionError(f"delegate {name} capability denied")
    delegate = delegates.get(name)
    if not delegate:
        raise PermissionError(f"delegate {name} is not configured")
    _validate_delegate_command(delegate, command)
    delegated = _build_delegate_command(delegate, command)
    env = _delegate_env(delegate)
    env = _inject_required_secret_env(env, delegate, command)
    return delegate, delegated, env


def run_delegate_proxy(capabilities, delegates, name, command):
    delegate, delegated, env = prepare_delegate_proxy(capabilities, delegates, name, command)
    note = _delegate_note(command)
    delegated_display = redact_argv(delegated, env=env)
    if delegate.get("mode") == "execute":
        proc = subprocess.run(delegated, text=True, capture_output=True, env=env)
        result = {
            "status": "ok" if proc.returncode == 0 else "error",
            "delegate": name,
            "command": list(command),
            "delegated_command": delegated_display,
            "returncode": proc.returncode,
            "stdout": proc.stdout,
            "stderr": proc.stderr,
        }
        if note:
            result["note"] = note
        return result
    result = {"status": "ok", "delegate": name, "command": list(command), "delegated_command": delegated_display}
    if note:
        result["note"] = note
    return result


def stream_delegate_proxy(capabilities, delegates, name, command, write_frame):
    _, delegated, env = prepare_delegate_proxy(capabilities, delegates, name, command)
    header = f"[delegate:{name}] {format_delegate_display(delegated, env=env)}\n"
    write_frame({"type": "header", "stream": "stderr", "text": header})
    note = _delegate_note(command)
    if note:
        write_frame({"type": "header", "stream": "stderr", "text": f"[delegate:{name}] note: {note}\n"})
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
    return delegated, returncode
