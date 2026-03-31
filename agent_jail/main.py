import argparse
import json
import os
import shutil
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime

from agent_jail.backend import build_command, choose_backend
from agent_jail.broker import BrokerServer
from agent_jail.capabilities import resolve_session_capabilities
from agent_jail.config import load_config
from agent_jail.policy import PolicyStore
from agent_jail.proxy import ProxyPolicy, start_proxy
from agent_jail.wrappers import write_wrappers

DEFAULT_KILL_SWITCH = "/tmp/agent-jail.stop"


def resolve_python():
    candidate = sys.executable or shutil.which("python3") or "python3"
    if os.path.isabs(candidate):
        return os.path.realpath(candidate)
    resolved = shutil.which(candidate)
    return os.path.realpath(resolved) if resolved else candidate


def resolve_target(target_argv, env):
    candidate = target_argv[0]
    if os.path.sep in candidate:
        resolved = os.path.abspath(os.path.expanduser(candidate))
        if os.path.exists(resolved):
            return [resolved, *target_argv[1:]]
        raise FileNotFoundError(candidate)
    resolved = shutil.which(candidate, path=env.get("PATH"))
    if resolved:
        return [os.path.realpath(resolved), *target_argv[1:]]
    raise FileNotFoundError(candidate)


def ensure_home():
    preferred = os.environ.get("AGENT_JAIL_HOME") or os.path.join(os.path.expanduser("~"), ".agent-jail")
    try:
        os.makedirs(preferred, exist_ok=True)
        return preferred
    except PermissionError:
        return tempfile.mkdtemp(prefix="agent-jail-home-")


def discover_cert_env():
    paths = ssl.get_default_verify_paths()
    updates = {}
    if paths.cafile and os.path.exists(paths.cafile):
        updates["SSL_CERT_FILE"] = paths.cafile
    if paths.capath and os.path.exists(paths.capath):
        updates["SSL_CERT_DIR"] = paths.capath
    return updates


def discover_tty_env():
    paths = {"/dev/stdin", "/dev/stdout", "/dev/stderr", "/dev/null", "/dev/fd"}
    try:
        ctermid = os.ctermid()
    except OSError:
        ctermid = None
    if ctermid:
        paths.add(ctermid)
    for fd in (0, 1, 2):
        try:
            paths.add(os.ttyname(fd))
        except OSError:
            continue
    if not paths:
        return {}
    return {"AGENT_JAIL_TTY_PATHS": json.dumps(sorted(paths))}


def prepare_home_mounts(home, mount_codex_home=True, mount_claude_home=True):
    os.makedirs(home, exist_ok=True)
    mounts = []
    options = [
        (mount_codex_home, ".codex"),
        (mount_claude_home, ".claude"),
    ]
    real_home = os.path.expanduser("~")
    for enabled, name in options:
        if not enabled:
            continue
        source = os.path.join(real_home, name)
        target = os.path.join(home, name)
        if not os.path.exists(source):
            continue
        if os.path.lexists(target):
            if os.path.islink(target) and os.path.realpath(target) == os.path.realpath(source):
                mounts.append({"source": source, "target": target, "mode": "rw"})
                continue
            if os.path.islink(target):
                os.unlink(target)
            else:
                backup = f"{target}.agent-jail-backup-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
                shutil.move(target, backup)
                mounts.append({"source": source, "target": target, "mode": "rw", "status": "backed-up-existing-target", "backup": backup})
        os.symlink(source, target)
        mounts.append({"source": source, "target": target, "mode": "rw"})
    compat_paths = ["build", "workspace"]
    for name in compat_paths:
        source = os.path.join(real_home, name)
        target = os.path.join(home, name)
        if not os.path.exists(source):
            continue
        if os.path.lexists(target):
            if os.path.islink(target) and os.path.realpath(target) == os.path.realpath(source):
                continue
            if os.path.islink(target):
                os.unlink(target)
            else:
                backup = f"{target}.agent-jail-backup-{datetime.now(UTC).strftime('%Y%m%d%H%M%S')}"
                shutil.move(target, backup)
        os.symlink(source, target)
    return mounts


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="agent-jail")
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser("run")
    run.add_argument("--proxy", action="store_true")
    run.add_argument("--deny-network-by-default", action="store_true")
    run.add_argument("--project", action="append", default=[])
    run.add_argument("--allow-write", action="append", default=[])
    run.add_argument("--allow-ops", action="store_true")
    run.add_argument("--allow-delegate", action="append", default=[])
    run.add_argument("--allow-browser", action="store_true")
    run.add_argument("--direct-secret-env", action="store_true")
    run.add_argument("--kill-switch")
    run.add_argument("--mount-codex-home", dest="mount_codex_home", action="store_true", default=True)
    run.add_argument("--no-mount-codex-home", dest="mount_codex_home", action="store_false")
    run.add_argument("--mount-claude-home", dest="mount_claude_home", action="store_true", default=True)
    run.add_argument("--no-mount-claude-home", dest="mount_claude_home", action="store_false")
    run.add_argument("target", nargs=argparse.REMAINDER)
    return parser, parser.parse_args(argv)


def run(argv=None):
    parser, args = parse_args(argv)
    if args.command != "run" or not args.target:
        parser.print_usage(sys.stderr)
        raise SystemExit(2)
    home = ensure_home()
    raw_kill_switch = args.kill_switch or DEFAULT_KILL_SWITCH
    kill_switch = os.path.abspath(os.path.expanduser(raw_kill_switch)) if raw_kill_switch else None
    if kill_switch and os.path.exists(kill_switch):
        print("agent-jail stopped by kill switch before launch", file=sys.stderr)
        raise SystemExit(125)
    config = load_config()
    with tempfile.TemporaryDirectory(prefix="agent-jail-") as tmp:
        source_root = os.path.dirname(os.path.dirname(__file__))
        python_executable = resolve_python()
        wrapper_dir = os.path.join(tmp, ".agent-jail", "bin")
        sock_path = os.path.join(tmp, "broker.sock")
        store = PolicyStore(os.path.join(home, "policy.json"))
        delegate_names = set(args.allow_delegate or [])
        if args.allow_ops:
            delegate_names.add("ops")
        session = resolve_session_capabilities(
            projects=args.project or [os.getcwd()],
            allow_write=args.allow_write or [os.getcwd()],
            skills_proxy=True,
            ops_exec=args.allow_ops,
            delegates=sorted(delegate_names),
            browser_automation=args.allow_browser,
            direct_secret_env=args.direct_secret_env,
        )
        broker = BrokerServer(sock_path, store, capabilities=session["capabilities"], delegates=config.get("delegates", []))
        broker_thread = threading.Thread(target=broker.serve_forever, daemon=True)
        broker_thread.start()
        write_wrappers(wrapper_dir, source_path=os.environ.get("PATH", ""), python_executable=python_executable)
        cap_target = os.path.join(wrapper_dir, "agent-jail-cap")
        source_cap = os.path.join(os.path.dirname(os.path.dirname(__file__)), "agent-jail-cap")
        shutil.copy2(source_cap, cap_target)
        os.chmod(cap_target, 0o755)
        auth_mounts = prepare_home_mounts(
            home,
            mount_codex_home=args.mount_codex_home,
            mount_claude_home=args.mount_claude_home,
        )
        env = os.environ.copy()
        env.update(
            {
                "AGENT_JAIL_HOME": home,
                "AGENT_JAIL_SOCKET": sock_path,
                "AGENT_JAIL_ORIG_PATH": env.get("PATH", ""),
                "AGENT_JAIL_MOUNTS": json.dumps(session["mounts"], sort_keys=True),
                "AGENT_JAIL_PYTHON": python_executable,
                "AGENT_JAIL_SESSION_DIR": tmp,
                "AGENT_JAIL_WRAPPER_DIR": wrapper_dir,
                "AGENT_JAIL_SOURCE_ROOT": source_root,
                "AGENT_JAIL_CAPABILITIES": json.dumps(session["capabilities"], sort_keys=True),
                "AGENT_JAIL_AUTH_MOUNTS": json.dumps(auth_mounts, sort_keys=True),
                "HOME": home,
                "PATH": wrapper_dir + os.pathsep + env.get("PATH", ""),
                "PYTHONPATH": source_root + os.pathsep + env.get("PYTHONPATH", ""),
            }
        )
        for key, value in discover_cert_env().items():
            env.setdefault(key, value)
        for key, value in discover_tty_env().items():
            env.setdefault(key, value)
        if kill_switch:
            env["AGENT_JAIL_KILL_SWITCH"] = kill_switch
        proxy_server = None
        if args.proxy:
            policy = ProxyPolicy(store.rules, default_allow=not args.deny_network_by_default)
            proxy_server, _ = start_proxy(policy)
            proxy_url = f"http://127.0.0.1:{proxy_server.server_port}"
            env.update({"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "ALL_PROXY": proxy_url})
        backend = choose_backend(preferred=env.get("AGENT_JAIL_BACKEND"))
        try:
            target_argv = resolve_target(args.target, env)
        except FileNotFoundError as exc:
            print(f"agent-jail: target command not found: {exc}", file=sys.stderr)
            return 127
        cmd = build_command(backend, target_argv, os.getcwd(), env)
        try:
            proc = subprocess.Popen(cmd, env=env, cwd=os.getcwd())
            while True:
                code = proc.poll()
                if code is not None:
                    return code
                if kill_switch and os.path.exists(kill_switch):
                    proc.terminate()
                    try:
                        proc.wait(timeout=1)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=1)
                    print("agent-jail stopped by kill switch", file=sys.stderr)
                    return 125
                time.sleep(0.1)
        finally:
            if proxy_server:
                proxy_server.shutdown()
                proxy_server.server_close()
            broker.close()


def main(argv=None):
    try:
        return run(argv)
    except SystemExit as exc:
        if isinstance(exc.code, int):
            return exc.code
        print(exc, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
