import argparse
import json
import os
import subprocess
import sys
import tempfile
import threading

from agent_jail.backend import build_command, choose_backend
from agent_jail.broker import BrokerServer
from agent_jail.capabilities import resolve_session_capabilities
from agent_jail.policy import PolicyStore
from agent_jail.proxy import ProxyPolicy, start_proxy
from agent_jail.wrappers import write_wrappers


def ensure_home():
    preferred = os.environ.get("AGENT_JAIL_HOME") or os.path.join(os.path.expanduser("~"), ".agent-jail")
    try:
        os.makedirs(preferred, exist_ok=True)
        return preferred
    except PermissionError:
        return tempfile.mkdtemp(prefix="agent-jail-home-")


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="agent-jail")
    sub = parser.add_subparsers(dest="command")
    run = sub.add_parser("run")
    run.add_argument("--proxy", action="store_true")
    run.add_argument("--deny-network-by-default", action="store_true")
    run.add_argument("--project", action="append", default=[])
    run.add_argument("--allow-write", action="append", default=[])
    run.add_argument("--allow-ops", action="store_true")
    run.add_argument("--allow-browser", action="store_true")
    run.add_argument("--direct-secret-env", action="store_true")
    run.add_argument("target", nargs=argparse.REMAINDER)
    return parser, parser.parse_args(argv)


def run(argv=None):
    parser, args = parse_args(argv)
    if args.command != "run" or not args.target:
        parser.print_usage(sys.stderr)
        raise SystemExit(2)
    home = ensure_home()
    with tempfile.TemporaryDirectory(prefix="agent-jail-") as tmp:
        wrapper_dir = os.path.join(tmp, ".agent-jail", "bin")
        sock_path = os.path.join(tmp, "broker.sock")
        store = PolicyStore(os.path.join(home, "policy.json"))
        session = resolve_session_capabilities(
            projects=args.project or [os.getcwd()],
            allow_write=args.allow_write or [os.getcwd()],
            skills_proxy=True,
            ops_exec=args.allow_ops,
            browser_automation=args.allow_browser,
            direct_secret_env=args.direct_secret_env,
        )
        broker = BrokerServer(sock_path, store, capabilities=session["capabilities"])
        broker_thread = threading.Thread(target=broker.serve_forever, daemon=True)
        broker_thread.start()
        write_wrappers(wrapper_dir, source_path=os.environ.get("PATH", ""), python_executable=sys.executable)
        env = os.environ.copy()
        env.update(
            {
                "AGENT_JAIL_HOME": home,
                "AGENT_JAIL_SOCKET": sock_path,
                "AGENT_JAIL_ORIG_PATH": env.get("PATH", ""),
                "AGENT_JAIL_PYTHON": sys.executable,
                "AGENT_JAIL_WRAPPER_DIR": wrapper_dir,
                "AGENT_JAIL_CAPABILITIES": json.dumps(session["capabilities"], sort_keys=True),
                "HOME": home,
                "PATH": wrapper_dir + os.pathsep + env.get("PATH", ""),
            }
        )
        proxy_server = None
        if args.proxy:
            policy = ProxyPolicy(store.rules, default_allow=not args.deny_network_by_default)
            proxy_server, _ = start_proxy(policy)
            proxy_url = f"http://127.0.0.1:{proxy_server.server_port}"
            env.update({"HTTP_PROXY": proxy_url, "HTTPS_PROXY": proxy_url, "ALL_PROXY": proxy_url})
        backend = choose_backend()
        cmd = build_command(backend, args.target, os.getcwd(), env)
        try:
            proc = subprocess.run(cmd, env=env, cwd=os.getcwd())
            return proc.returncode
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
