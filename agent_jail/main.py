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
from agent_jail.config import load_config, save_config
from agent_jail.events import EventSink, load_runtime_state, render_event, stream_event_socket, write_runtime_state
from agent_jail.policy import PolicyStore
from agent_jail.proxy import ProxyPolicy, start_proxy
from agent_jail.rule_suggestions import apply_suggestions, build_rule_suggestions
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
    run.add_argument("--allow-ops", dest="allow_ops", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--allow-delegate", action="append", default=[])
    run.add_argument("--allow-browser", action="store_true")
    run.add_argument("--direct-secret-env", action="store_true")
    run.add_argument("--kill-switch")
    run.add_argument("--mount-codex-home", dest="mount_codex_home", action="store_true", default=True)
    run.add_argument("--no-mount-codex-home", dest="mount_codex_home", action="store_false")
    run.add_argument("--mount-claude-home", dest="mount_claude_home", action="store_true", default=True)
    run.add_argument("--no-mount-claude-home", dest="mount_claude_home", action="store_false")
    run.add_argument("target", nargs=argparse.REMAINDER)
    monitor = sub.add_parser("monitor")
    monitor.add_argument("--follow", action="store_true")
    monitor.add_argument("--json", action="store_true")
    monitor.add_argument("--log")
    monitor.add_argument("--socket")
    suggest = sub.add_parser("suggest-rules")
    suggest.add_argument("--json", action="store_true")
    suggest.add_argument("--apply-low-risk", action="store_true")
    suggest.add_argument("--limit", type=int, default=500)
    suggest.add_argument("--log", action="append", default=[])
    review = sub.add_parser("review")
    review_sub = review.add_subparsers(dest="review_command", required=True)
    review_list = review_sub.add_parser("list")
    review_list.add_argument("--json", action="store_true")
    review_approve = review_sub.add_parser("approve")
    review_approve.add_argument("review_id")
    review_reject = review_sub.add_parser("reject")
    review_reject.add_argument("review_id")
    config = sub.add_parser("config")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("show")
    config_set = config_sub.add_parser("set-defaults")
    config_set.add_argument("--read-only-root", action="append", default=[])
    config_set.add_argument("--write-root", action="append", default=[])
    config_set.add_argument("--allow-ops", dest="allow_ops", action=argparse.BooleanOptionalAction, default=None)
    config_set.add_argument("--project-mode", choices=["cwd"], default=None)
    return parser, parser.parse_args(argv)


def runtime_state_path(home):
    return os.path.join(home, "runtime.json")


def _print_event(event, json_output=False):
    if json_output:
        print(json.dumps(event, sort_keys=True), flush=True)
    else:
        print(render_event(event), flush=True)


def _tail_log_from_offset(log_path, offset, json_output=False):
    if not os.path.exists(log_path):
        return offset
    with open(log_path, encoding="utf-8") as handle:
        handle.seek(offset)
        while True:
            line = handle.readline()
            if not line:
                break
            offset = handle.tell()
            line = line.strip()
            if not line:
                continue
            _print_event(json.loads(line), json_output=json_output)
    return offset


def monitor_events(args):
    home = ensure_home()
    state = {}
    state_path = runtime_state_path(home)
    if args.log or args.socket:
        log_path = os.path.abspath(os.path.expanduser(args.log)) if args.log else None
        socket_path = os.path.abspath(os.path.expanduser(args.socket)) if args.socket else None
    else:
        try:
            state = load_runtime_state(state_path)
        except FileNotFoundError:
            print("agent-jail monitor: no runtime state found", file=sys.stderr)
            return 2
        log_path = state.get("events_log")
        socket_path = state.get("events_socket")
    if not log_path:
        print("agent-jail monitor: no event log configured", file=sys.stderr)
        return 2
    if os.path.exists(log_path):
        with open(log_path, encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                _print_event(json.loads(line), json_output=args.json)
    if not args.follow:
        return 0
    if args.log or args.socket:
        if socket_path and os.path.exists(socket_path):
            for event in stream_event_socket(socket_path):
                _print_event(event, json_output=args.json)
            return 0
        offset = os.path.getsize(log_path) if os.path.exists(log_path) else 0
        while True:
            offset = _tail_log_from_offset(log_path, offset, json_output=args.json)
            time.sleep(0.1)

    seen_socket = socket_path
    offset = os.path.getsize(log_path) if os.path.exists(log_path) else 0
    while True:
        try:
            state = load_runtime_state(state_path)
        except FileNotFoundError:
            state = {}
        current_log = state.get("events_log") or log_path
        current_socket = state.get("events_socket")
        if current_log != log_path:
            log_path = current_log
            offset = 0
            seen_socket = None
        offset = _tail_log_from_offset(log_path, offset, json_output=args.json)
        if current_socket and current_socket != seen_socket and os.path.exists(current_socket):
            seen_socket = current_socket
            for event in stream_event_socket(current_socket):
                _print_event(event, json_output=args.json)
            continue
        time.sleep(0.1)


def suggest_rules(args):
    home = ensure_home()
    config = load_config()
    store = PolicyStore(os.path.join(home, "policy.json"))
    log_paths = [os.path.abspath(os.path.expanduser(path)) for path in (args.log or [])]
    result = build_rule_suggestions(store, config, event_paths=log_paths or None, limit=args.limit)
    applied = []
    if args.apply_low_risk:
        applied = apply_suggestions(store, result["suggestions"], auto_only=True)
    output = {
        "clusters": result["clusters"],
        "suggestions": result["suggestions"],
        "applied": applied,
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(f"clusters: {len(result['clusters'])}")
        print(f"suggestions: {len(result['suggestions'])}")
        print(f"applied: {len(applied)}")
        for item in result["suggestions"]:
            rule = item["rule"]
            template = rule.get("metadata", {}).get("template", "")
            state = "auto" if item.get("auto_promote") else "suggested"
            print(f"- [{state}] {template} -> allow {rule['tool']} {rule['action']}")
    return 0


def review_rule_from_pending(review):
    rule = review.get("rule")
    if rule:
        return rule
    return {
        "kind": "exec",
        "tool": review["tool"],
        "action": review["action"],
        "allow": True,
        "constraints": {},
        "metadata": {
            "promotion_state": "user-approved",
            "source": "review",
            "template": review.get("template", ""),
            "rationale": review.get("reason", ""),
        },
    }


def handle_review(args):
    home = ensure_home()
    store = PolicyStore(os.path.join(home, "policy.json"))
    if args.review_command == "list":
        reviews = store.pending_reviews
        if args.json:
            print(json.dumps(reviews, indent=2, sort_keys=True))
        else:
            print(f"pending: {len(reviews)}")
            for review in reviews:
                template = review.get("template") or review.get("raw")
                print(f"- {review['id']} | {review.get('tool')} {review.get('action')} | {template}")
        return 0
    review = store.get_pending_review(args.review_id)
    if not review:
        print(f"agent-jail review: unknown id {args.review_id}", file=sys.stderr)
        return 2
    if args.review_command == "approve":
        rule = review_rule_from_pending(review)
        metadata = dict(rule.get("metadata", {}))
        metadata["promotion_state"] = "user-approved"
        applied = store.add_rule({**rule, "metadata": metadata})
        store.remove_pending_review(args.review_id)
        print("approved" if applied else "already-approved")
        return 0
    store.remove_pending_review(args.review_id)
    print("rejected")
    return 0


def handle_config(args):
    home = ensure_home()
    config_path = os.path.join(home, "config.json")
    config = load_config(config_path)
    if args.config_command == "show":
        print(json.dumps(config, indent=2, sort_keys=True))
        return 0
    run_defaults = dict(config.get("defaults", {}).get("run", {}))
    if args.read_only_root:
        run_defaults["read_only_roots"] = [os.path.abspath(os.path.expanduser(path)) for path in args.read_only_root]
    if args.write_root:
        run_defaults["write_roots"] = [os.path.abspath(os.path.expanduser(path)) for path in args.write_root]
    if args.allow_ops is not None:
        run_defaults["allow_ops"] = bool(args.allow_ops)
    if args.project_mode is not None:
        run_defaults["project_mode"] = args.project_mode
    config.setdefault("defaults", {})
    config["defaults"]["run"] = run_defaults
    save_config(config, config_path)
    print(json.dumps(load_config(config_path), indent=2, sort_keys=True))
    return 0


def run(argv=None):
    parser, args = parse_args(argv)
    if args.command == "monitor":
        return monitor_events(args)
    if args.command == "review":
        return handle_review(args)
    if args.command == "suggest-rules":
        return suggest_rules(args)
    if args.command == "config":
        return handle_config(args)
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
    run_defaults = config.get("defaults", {}).get("run", {})
    with tempfile.TemporaryDirectory(prefix="agent-jail-") as tmp:
        source_root = os.path.dirname(os.path.dirname(__file__))
        python_executable = resolve_python()
        wrapper_dir = os.path.join(tmp, ".agent-jail", "bin")
        sock_path = os.path.join(tmp, "broker.sock")
        event_socket_path = os.path.join(tmp, "events.sock")
        event_log_path = os.path.join(
            home,
            "events",
            f"session-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{os.getpid()}.jsonl",
        )
        store = PolicyStore(os.path.join(home, "policy.json"))
        delegate_names = set(args.allow_delegate or [])
        allow_ops = run_defaults.get("allow_ops", False) if args.allow_ops is None else bool(args.allow_ops)
        if allow_ops:
            delegate_names.add("ops")
        projects = list(args.project)
        allow_write = list(args.allow_write)
        cwd = os.getcwd()
        if run_defaults.get("project_mode") == "cwd" and not projects:
            projects.append(cwd)
        if cwd in projects and cwd not in allow_write:
            allow_write.append(cwd)
        session = resolve_session_capabilities(
            projects=projects or [cwd],
            allow_write=allow_write or [cwd],
            read_only_roots=config.get("filesystem", {}).get("read_only_roots", []) + run_defaults.get("read_only_roots", []),
            write_roots=config.get("filesystem", {}).get("write_roots", []) + run_defaults.get("write_roots", []),
            skills_proxy=True,
            ops_exec=allow_ops,
            delegates=sorted(delegate_names),
            browser_automation=args.allow_browser,
            direct_secret_env=args.direct_secret_env,
        )
        event_sink = EventSink(event_log_path, socket_path=event_socket_path)
        event_sink.start()
        write_runtime_state(
            runtime_state_path(home),
            {
                "active": True,
                "cwd": os.getcwd(),
                "events_log": event_log_path,
                "events_socket": event_socket_path,
                "pid": os.getpid(),
                "started_at": datetime.now(UTC).isoformat(),
            },
        )
        broker = BrokerServer(
            sock_path,
            store,
            capabilities=session["capabilities"],
            delegates=config.get("delegates", []),
            mounts=session["mounts"],
            deny_read_patterns=config.get("filesystem", {}).get("deny_read_patterns", []),
            event_sink=event_sink,
            log_stderr=bool(os.environ.get("AGENT_JAIL_LOG_STDERR")),
            llm_policy=config.get("llm_policy", {}),
        )
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
                "AGENT_JAIL_DENY_READ_PATTERNS": json.dumps(
                    config.get("filesystem", {}).get("deny_read_patterns", []), sort_keys=True
                ),
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
            event_sink.close()
            write_runtime_state(
                runtime_state_path(home),
                {
                    "active": False,
                    "cwd": os.getcwd(),
                    "events_log": event_log_path,
                    "events_socket": None,
                    "ended_at": datetime.now(UTC).isoformat(),
                    "pid": os.getpid(),
                },
            )


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
