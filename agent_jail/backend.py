import os
import platform
import shutil


def choose_backend(system=None, have=None):
    system = (system or platform.system()).lower()
    have = have or shutil.which
    if system.startswith("linux"):
        if have("bwrap"):
            return {"name": "bubblewrap"}
        if have("proot"):
            return {"name": "proot"}
    return {"name": "host"}


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
    return list(target_argv)
