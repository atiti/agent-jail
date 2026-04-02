import json
import fnmatch
import os
import platform
import shutil
from pathlib import Path

DARWIN_GLOBAL_MACH_SERVICES = (
    "com.apple.SystemConfiguration.configd",
    "com.apple.SystemConfiguration.SCNetworkReachability",
    "com.apple.notifyd",
    "com.apple.trustd",
    "com.apple.securityd",
    "com.apple.SecurityServer",
    "com.apple.ocspd",
    "com.apple.cfprefsd.agent",
    "com.apple.nsurlstorage-cache",
)

DARWIN_TTY_IOCTL_REGEX = '^/dev/tty.*'


def choose_backend(system=None, have=None, preferred=None):
    system = (system or platform.system()).lower()
    have = have or shutil.which
    if preferred and preferred != "auto":
        return {"name": preferred}
    if system.startswith("linux"):
        if have("bwrap"):
            return {"name": "bubblewrap"}
        if have("proot"):
            return {"name": "proot"}
    if system.startswith("darwin"):
        if have("sandbox-exec"):
            return {"name": "sandbox-exec"}
        if have("alcless"):
            return {"name": "alcless"}
    return {"name": "host"}


def _load_json_list(env, key):
    raw = env.get(key)
    if not raw:
        return []
    try:
        value = json.loads(raw)
    except json.JSONDecodeError:
        return []
    return value if isinstance(value, list) else []


def _profile_quote(path):
    return '"' + path.replace("\\", "\\\\").replace('"', '\\"') + '"'


def _writable_paths(cwd, env):
    writable = {"/tmp", cwd}
    tmpdir = env.get("TMPDIR")
    if tmpdir:
        writable.add(tmpdir)
    session_dir = env.get("AGENT_JAIL_SESSION_DIR")
    if session_dir:
        writable.add(session_dir)
    for path in _load_json_list(env, "AGENT_JAIL_TTY_PATHS"):
        if path:
            writable.add(path)
    home = env.get("AGENT_JAIL_HOME")
    if home:
        writable.add(home)
    for mount in _load_json_list(env, "AGENT_JAIL_MOUNTS"):
        path = mount.get("path")
        if path and mount.get("mode") == "rw":
            writable.add(path)
    for mount in _load_json_list(env, "AGENT_JAIL_AUTH_MOUNTS"):
        for key in ("source", "target"):
            path = mount.get(key)
            if path:
                writable.add(path)
    if platform.system().lower().startswith("darwin"):
        for path in list(writable):
            cache_dir = _darwin_user_cache_dir(path)
            if cache_dir:
                writable.add(cache_dir)
        # `/var` and `/tmp` commonly resolve through `/private/...` on macOS.
        # Include both spellings so Security.framework cache writes keep working.
        for path in list(writable):
            real = os.path.realpath(path)
            if real:
                writable.add(real)
    return sorted(path for path in writable if path)


def _darwin_user_cache_dir(path):
    try:
        candidate = Path(path)
    except TypeError:
        return None
    parts = candidate.parts
    if len(parts) >= 6 and parts[1] == "var" and parts[2] == "folders":
        root = Path(*parts[:5])
        return str(root / "C")
    if len(parts) >= 7 and parts[1] == "private" and parts[2] == "var" and parts[3] == "folders":
        root = Path(*parts[:6])
        return str(root / "C")
    return None


def _deny_read_patterns(env):
    return [item for item in _load_json_list(env, "AGENT_JAIL_DENY_READ_PATTERNS") if isinstance(item, str) and item]


def _pattern_to_regex(pattern):
    translated = fnmatch.translate(pattern)
    if translated.endswith("\\Z"):
        translated = translated[:-2]
    return translated


def _darwin_denied_exec_paths(env):
    denied = []
    git_ssh_hosts = _load_json_list(env, "AGENT_JAIL_GIT_SSH_HOSTS")
    if not git_ssh_hosts:
        denied.append("/usr/bin/ssh")
    return denied


def build_sandbox_exec_profile(cwd, env):
    writable = _writable_paths(cwd, env)
    deny_patterns = _deny_read_patterns(env)
    lines = [
        "(version 1)",
        '(import "system.sb")',
        "(deny default)",
        "(deny process-exec",
    ]
    for path in _darwin_denied_exec_paths(env):
        lines.append(f"    (literal {_profile_quote(path)})")
    lines.extend(
        [
            ")",
            "(allow process*)",
            "(allow process-exec)",
        ]
    )
    lines.extend(
        [
        "(allow signal (target self))",
        "(allow sysctl-read)",
        "(deny file-read*",
        ]
    )
    for pattern in deny_patterns:
        lines.append(f'    (regex #"{_pattern_to_regex(pattern)}")')
    lines.extend(
        [
        ")",
        "(allow file-read*)",
        "(allow file-map-executable)",
        "(allow file-ioctl",
        f'    (regex #"{DARWIN_TTY_IOCTL_REGEX}")',
        ")",
        "(allow network*)",
        "(allow mach-lookup",
        ]
    )
    for service in DARWIN_GLOBAL_MACH_SERVICES:
        lines.append(f"    (global-name {_profile_quote(service)})")
    lines.extend(
        [
            ")",
            "(allow file-write*",
        ]
    )
    for path in writable:
        lines.append(f"    (subpath {_profile_quote(path)})")
    lines.append(")")
    return "\n".join(lines) + "\n"


def build_command(backend, target_argv, cwd, env):
    name = backend["name"]
    if name == "bubblewrap":
        cmd = ["bwrap", "--die-with-parent", "--ro-bind", "/", "/", "--proc", "/proc", "--dev-bind", "/dev", "/dev"]
        for path in {cwd, env.get("AGENT_JAIL_HOME", "")}:
            if path and os.path.exists(path):
                cmd += ["--bind", path, path]
        cmd += ["--chdir", cwd]
        for key in ("PATH", "HOME", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "AGENT_JAIL_SOCKET", "AGENT_JAIL_ORIG_PATH", "AGENT_JAIL_PYTHON", "AGENT_JAIL_WRAPPER_DIR"):
            if env.get(key):
                cmd += ["--setenv", key, env[key]]
        return cmd + target_argv
    if name == "proot":
        cmd = ["proot", "-R", "/", "-w", cwd, "-b", f"{cwd}:{cwd}"]
        home = env.get("AGENT_JAIL_HOME")
        if home and os.path.exists(home):
            cmd += ["-b", f"{home}:{home}"]
        return cmd + target_argv
    if name == "sandbox-exec":
        session_dir = env.get("AGENT_JAIL_SESSION_DIR") or cwd
        profile_path = os.path.join(session_dir, "sandbox.sb")
        with open(profile_path, "w", encoding="utf-8") as handle:
            handle.write(build_sandbox_exec_profile(cwd, env))
        return ["sandbox-exec", "-f", profile_path, *target_argv]
    if name == "alcless":
        return ["alcless", "--plain", *target_argv]
    return list(target_argv)
