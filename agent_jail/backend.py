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
    "com.apple.security",
    "com.apple.securityd",
    "com.apple.security.smartcard",
    "com.apple.SecurityServer",
    "com.apple.TrustEvaluationAgent",
    "com.apple.system.opendirectoryd.api",
    "com.apple.ocspd",
    "com.apple.nsurlstorage-cache",
)

DARWIN_LOCAL_MACH_SERVICES = ()

DARWIN_IPC_POSIX_SHM_NAMES = (
    "apple.shm.cfprefsd.daemon",
)

DARWIN_IPC_POSIX_SHM_PREFIXES = (
    "apple.shm.cfprefsd.",
)

DARWIN_TTY_IOCTL_REGEX = '^/dev/tty.*'
DARWIN_DIRECTORYSERVICE_SOCKETS = (
    "/private/var/run/ldapi",
    "/var/run/ldapi",
)
DARWIN_SYSTEM_READ_SUBPATHS = (
    "/bin",
    "/sbin",
    "/usr",
    "/System",
    "/Library",
    "/opt",
    "/dev",
    "/private/etc",
    "/private/var/db/mds",
)

DARWIN_METADATA_READ_PATHS = (
    "/Users",
    "/private/var/db/mds/system/mdsObject.db",
)


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


def _profile_path_rule(path):
    kind = "subpath"
    if os.path.exists(path) and not os.path.isdir(path):
        kind = "literal"
    return f"    ({kind} {_profile_quote(path)})"


def _add_path_with_parent(paths, path):
    if not path:
        return
    paths.add(path)
    if os.path.exists(path) and not os.path.isdir(path):
        parent = os.path.dirname(path)
        if parent:
            paths.add(parent)


def _add_path(paths, path):
    if path:
        paths.add(path)


def _iter_parent_dirs(path):
    parent = os.path.dirname(path)
    seen = set()
    while parent and parent not in seen and parent != os.path.sep:
        seen.add(parent)
        yield parent
        parent = os.path.dirname(parent)


def _metadata_paths(cwd, env):
    metadata = set(DARWIN_METADATA_READ_PATHS)
    for mount in _load_json_list(env, "AGENT_JAIL_AUTH_MOUNTS"):
        for key in ("source", "target"):
            path = mount.get(key)
            if not path or not os.path.exists(path) or os.path.isdir(path):
                continue
            metadata.update(_iter_parent_dirs(path))
            real = os.path.realpath(path)
            if real and real != path:
                metadata.update(_iter_parent_dirs(real))
    return sorted(path for path in metadata if path)


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
            _add_path(writable, path)
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


def _readable_paths(cwd, env):
    readable = {cwd, "/tmp"}
    tmpdir = env.get("TMPDIR")
    if tmpdir:
        readable.add(tmpdir)
    session_dir = env.get("AGENT_JAIL_SESSION_DIR")
    if session_dir:
        readable.add(session_dir)
    home = env.get("AGENT_JAIL_HOME")
    if home:
        readable.add(home)
    for mount in _load_json_list(env, "AGENT_JAIL_MOUNTS"):
        path = mount.get("path")
        if path:
            readable.add(path)
    for mount in _load_json_list(env, "AGENT_JAIL_AUTH_MOUNTS"):
        for key in ("source", "target"):
            path = mount.get(key)
            _add_path(readable, path)
    for path in env.get("PYTHONPATH", "").split(os.pathsep):
        if path:
            readable.add(path)
    if platform.system().lower().startswith("darwin"):
        for path in list(readable):
            cache_dir = _darwin_user_cache_dir(path)
            if cache_dir:
                readable.add(cache_dir)
        for path in list(readable):
            real = os.path.realpath(path)
            if real:
                readable.add(real)
    return sorted(path for path in readable if path)


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
    denied = set()
    git_ssh_hosts = _load_json_list(env, "AGENT_JAIL_GIT_SSH_HOSTS")
    if not git_ssh_hosts:
        denied.add("/usr/bin/ssh")
    return sorted(path for path in denied if path)


def build_sandbox_exec_profile(cwd, env):
    writable = _writable_paths(cwd, env)
    readable = _readable_paths(cwd, env)
    metadata = _metadata_paths(cwd, env)
    deny_patterns = _deny_read_patterns(env)
    lines = [
        "(version 1)",
        '(import "system.sb")',
        '(import "com.apple.corefoundation.sb")',
        "(deny default)",
        "(corefoundation)",
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
            "(allow file-read*",
        ]
    )
    for path in DARWIN_SYSTEM_READ_SUBPATHS:
        lines.append(_profile_path_rule(path))
    for path in readable:
        lines.append(_profile_path_rule(path))
    lines.extend(
        [
            ")",
            "(allow user-preference-read",
            '    (preference-domain "kCFPreferencesAnyApplication")',
            '    (preference-domain "com.apple.security")',
            '    (preference-domain "com.apple.security_common")',
            '    (preference-domain "com.apple.security.smartcard")',
            '    (preference-domain "securityd")',
            ")",
            "(allow file-read-metadata",
        ]
    )
    for path in metadata:
        lines.append(f"    (literal {_profile_quote(path)})")
    lines.extend(
        [
            ")",
            "(allow file-map-executable)",
            '(allow network* (local ip "localhost:*"))',
            '(allow network* (remote ip "localhost:*"))',
            "(allow network-outbound (to unix-socket))",
            "(allow ipc-posix-shm-read*",
        ]
    )
    for name in DARWIN_IPC_POSIX_SHM_NAMES:
        lines.append(f"    (ipc-posix-name {_profile_quote(name)})")
    for prefix in DARWIN_IPC_POSIX_SHM_PREFIXES:
        lines.append(f"    (ipc-posix-name-prefix {_profile_quote(prefix)})")
    lines.extend(
        [
            ")",
            "(allow network-outbound",
        ]
    )
    for path in DARWIN_DIRECTORYSERVICE_SOCKETS:
        lines.append(f"    (literal {_profile_quote(path)})")
    lines.extend(
        [
            ")",
            "(allow file-ioctl",
            f'    (regex #"{DARWIN_TTY_IOCTL_REGEX}")',
            ")",
            "(allow mach-lookup",
        ]
    )
    for service in DARWIN_GLOBAL_MACH_SERVICES:
        lines.append(f"    (global-name {_profile_quote(service)})")
    lines.extend(
        [
            *(f"    (local-name {_profile_quote(service)})" for service in DARWIN_LOCAL_MACH_SERVICES),
            ")",
            "(allow file-write*",
        ]
    )
    for path in writable:
        lines.append(_profile_path_rule(path))
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
