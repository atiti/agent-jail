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
from agent_jail.proxy import ProxyPolicy, start_http_proxy, start_socks_proxy
from agent_jail.rule_suggestions import apply_suggestions, build_rule_suggestions
from agent_jail.wrappers import write_wrappers

ANSI_RESET = "\033[0m"
ANSI_DIM = "\033[2m"
ANSI_YELLOW = "\033[33m"

DEFAULT_KILL_SWITCH = "/tmp/agent-jail.stop"
DARWIN_SYSTEM_ROOT_KEYCHAIN = "/System/Library/Keychains/SystemRootCertificates.keychain"
DARWIN_SYSTEM_ROOT_PEM_NAME = "macos-system-roots.pem"
CAP_LAUNCHER_TEMPLATE = """#!/bin/sh

REPO_ROOT="{repo_root}"
PYTHON_BIN="{python_bin}"

if [ -n "$PYTHONPATH" ]; then
  export PYTHONPATH="$REPO_ROOT:$PYTHONPATH"
else
  export PYTHONPATH="$REPO_ROOT"
fi

exec "$PYTHON_BIN" -m agent_jail.cap_cli "$@"
"""


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


def render_cap_launcher(repo_root, python_bin):
    return CAP_LAUNCHER_TEMPLATE.format(
        repo_root=repo_root.replace('"', '\\"'),
        python_bin=python_bin.replace('"', '\\"'),
    )


TARGET_ENV_PROFILES = {
    "codex": {
        "clear": {
            "http_proxy",
            "https_proxy",
            "all_proxy",
            "socks_proxy",
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "SOCKS_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
            "REQUESTS_CA_BUNDLE",
            "CURL_CA_BUNDLE",
            "NODE_EXTRA_CA_CERTS",
        },
        "preserve": {
            "HTTP_PROXY",
            "HTTPS_PROXY",
            "ALL_PROXY",
            "SOCKS_PROXY",
            "AGENT_JAIL_HTTP_PROXY",
            "AGENT_JAIL_SOCKS_PROXY",
            "SSL_CERT_FILE",
            "SSL_CERT_DIR",
        },
    }
}


def apply_target_env_profile(env, target_argv, proxy_mode=None):
    if not target_argv:
        return env
    target_name = os.path.basename(target_argv[0])
    profile = TARGET_ENV_PROFILES.get(target_name)
    if not profile:
        return env
    preserved = {key: env[key] for key in profile["preserve"] if key in env}
    for key in profile["clear"]:
        env.pop(key, None)
    env.update(preserved)
    if target_name == "codex" and proxy_mode is None:
        system_cert_file = env.get("AGENT_JAIL_SYSTEM_CERT_FILE")
        if env.get("SSL_CERT_FILE") != system_cert_file:
            env.pop("SSL_CERT_FILE", None)
        env.pop("SSL_CERT_DIR", None)
    if target_name == "codex" and proxy_mode in {"codex-http", "codex-http-native"}:
        for key in ("ALL_PROXY", "SOCKS_PROXY", "SSL_CERT_DIR"):
            env.pop(key, None)
        if proxy_mode == "codex-http-native":
            env.pop("SSL_CERT_FILE", None)
    return env


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
    if sys.platform == "darwin":
        # Native macOS TLS clients can use a PEM bundle, but exporting the OpenSSL
        # cert directory has caused proxy/TLS compatibility issues with Codex.
        return updates
    if paths.capath and os.path.exists(paths.capath):
        updates["SSL_CERT_DIR"] = paths.capath
    return updates


def discover_macos_system_cert_env(session_dir):
    if sys.platform != "darwin" or not session_dir:
        return {}
    try:
        os.makedirs(session_dir, exist_ok=True)
    except OSError:
        return {}
    pem_path = os.path.join(session_dir, DARWIN_SYSTEM_ROOT_PEM_NAME)
    result = subprocess.run(
        [
            "/usr/bin/security",
            "find-certificate",
            "-a",
            "-p",
            DARWIN_SYSTEM_ROOT_KEYCHAIN,
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return {}
    with open(pem_path, "w", encoding="utf-8") as handle:
        handle.write(result.stdout)
    return {
        "SSL_CERT_FILE": pem_path,
        "AGENT_JAIL_SYSTEM_CERT_FILE": pem_path,
    }


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


def discover_auxiliary_read_roots():
    roots = []
    for path in (
        os.path.join(os.path.expanduser("~"), ".codex"),
        os.path.join(os.path.expanduser("~"), ".agents"),
    ):
        if os.path.exists(path):
            roots.append(path)
    return roots


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
    run.add_argument("--proxy", dest="proxy", action=argparse.BooleanOptionalAction, default=None)
    run.add_argument("--proxy-commands-only", action="store_true")
    run.add_argument(
        "--proxy-mode",
        choices=["http", "socks", "hybrid", "codex-http", "codex-http-native"],
        default="hybrid",
    )
    run.add_argument("--proxy-debug", action="store_true")
    run.add_argument("--print-launch-env", action="store_true")
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
    monitor.add_argument("--session", action="append", default=[])
    suggest = sub.add_parser("suggest-rules")
    suggest.add_argument("--json", action="store_true")
    suggest.add_argument("--apply-low-risk", action="store_true")
    suggest.add_argument("--interactive", action="store_true")
    suggest.add_argument("--limit", type=int, default=500)
    suggest.add_argument("--log", action="append", default=[])
    review = sub.add_parser("review")
    review_sub = review.add_subparsers(dest="review_command", required=True)
    review_list = review_sub.add_parser("list")
    review_list.add_argument("--json", action="store_true")
    review_list.add_argument("--all", action="store_true")
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
    config_set.add_argument("--proxy", dest="proxy", action=argparse.BooleanOptionalAction, default=None)
    config_set.add_argument("--allow-ops", dest="allow_ops", action=argparse.BooleanOptionalAction, default=None)
    config_set.add_argument("--allow-delegate", action="append", default=[])
    config_set.add_argument("--project-mode", choices=["cwd"], default=None)
    network = sub.add_parser("network")
    network_sub = network.add_subparsers(dest="network_command", required=True)
    for name in ("allow", "deny", "test"):
        command = network_sub.add_parser(name)
        command.add_argument("host")
        command.add_argument("--port", type=int)
        command.add_argument("--scheme", default="tcp")
        if name == "test":
            command.add_argument("--default-deny", action="store_true")
    network_list = network_sub.add_parser("list")
    network_list.add_argument("--json", action="store_true")
    return parser, parser.parse_args(argv)


def runtime_state_path(home):
    return os.path.join(home, "runtime.json")


def runtime_states_dir(home):
    return os.path.join(home, "runtimes")


def runtime_state_record_path(home, session):
    return os.path.join(runtime_states_dir(home), f"{session}.json")


def list_runtime_states(home):
    states = []
    directory = runtime_states_dir(home)
    if not os.path.isdir(directory):
        return states
    for entry in sorted(os.listdir(directory)):
        if not entry.endswith(".json"):
            continue
        path = os.path.join(directory, entry)
        try:
            state = load_runtime_state(path)
        except (FileNotFoundError, json.JSONDecodeError):
            continue
        state.setdefault("session", entry[:-5])
        states.append(state)
    return states


def _print_event(event, json_output=False):
    if json_output:
        print(json.dumps(event, sort_keys=True), flush=True)
    else:
        color = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
        print(render_event(event, color=color), flush=True)


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


def _selected_runtime_states(home, session_filters=None):
    states = list_runtime_states(home)
    wanted = set(session_filters or [])
    if wanted:
        selected = [state for state in states if state.get("session") in wanted]
        return sorted(selected, key=lambda item: item.get("session", ""))
    active = [state for state in states if state.get("active")]
    if active:
        return sorted(active, key=lambda item: item.get("session", ""))
    try:
        state = load_runtime_state(runtime_state_path(home))
    except FileNotFoundError:
        return []
    if state:
        state.setdefault("session", state.get("session", "latest"))
        return [state]
    return []


def monitor_events(args):
    home = ensure_home()
    if args.log or args.socket:
        log_path = os.path.abspath(os.path.expanduser(args.log)) if args.log else None
        socket_path = os.path.abspath(os.path.expanduser(args.socket)) if args.socket else None
    else:
        states = _selected_runtime_states(home, session_filters=args.session)
        if not states:
            print("agent-jail monitor: no matching runtime state found", file=sys.stderr)
            return 2
        log_path = None
        socket_path = None
    if not log_path:
        if args.log or args.socket:
            print("agent-jail monitor: no event log configured", file=sys.stderr)
            return 2
        log_offsets = {}
        for state in states:
            state_log = state.get("events_log")
            if not state_log:
                continue
            log_offsets[state_log] = 0
            if os.path.exists(state_log):
                with open(state_log, encoding="utf-8") as handle:
                    for line in handle:
                        line = line.strip()
                        if not line:
                            continue
                        _print_event(json.loads(line), json_output=args.json)
                log_offsets[state_log] = os.path.getsize(state_log)
        if not log_offsets:
            print("agent-jail monitor: no event log configured", file=sys.stderr)
            return 2
    elif os.path.exists(log_path):
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
    while True:
        current_states = _selected_runtime_states(home, session_filters=args.session)
        current_logs = {
            state.get("events_log")
            for state in current_states
            if state.get("events_log")
        }
        for current_log in sorted(current_logs):
            offset = log_offsets.get(current_log, 0)
            log_offsets[current_log] = _tail_log_from_offset(current_log, offset, json_output=args.json)
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
    if args.interactive and args.json:
        print("agent-jail suggest-rules: --interactive cannot be combined with --json", file=sys.stderr)
        return 2
    output = {
        "clusters": result["clusters"],
        "suggestions": result["suggestions"],
        "applied": applied,
    }
    if args.json:
        print(json.dumps(output, indent=2, sort_keys=True))
    else:
        print(_format_suggestion_report(result["clusters"], result["suggestions"], applied))
        if args.interactive:
            review_result = _review_suggestions_interactively(store, result["suggestions"])
            print(_format_interactive_summary(review_result))
    return 0


def _supports_color(stream):
    return bool(getattr(stream, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")


def _color(text, code, stream=sys.stdout):
    if not _supports_color(stream):
        return text
    return f"{code}{text}\033[0m"


def _format_suggestion_line(index, item, stream=sys.stdout):
    rule = item["rule"]
    meta = rule.get("metadata", {})
    template = meta.get("template", "")
    source = meta.get("source", "unknown")
    observations = meta.get("observations", 0)
    confidence = float(meta.get("confidence", 0.0))
    status = "AUTO" if item.get("auto_promote") else "REVIEW"
    status_color = "\033[32m" if item.get("auto_promote") else "\033[33m"
    status_text = _color(status, status_color, stream=stream)
    return (
        f"{index}. [{status_text}] {template} -> allow {rule['tool']} {rule['action']} "
        f"(seen {observations}x, confidence {confidence:.2f}, source {source})"
    )


def _format_suggestion_report(clusters, suggestions, applied, stream=sys.stdout):
    lines = [
        _color("Suggestion Summary", "\033[1m", stream=stream),
        f"clusters: {len(clusters)}",
        f"suggestions: {len(suggestions)}",
        f"applied: {len(applied)}",
    ]
    auto = [item for item in suggestions if item.get("auto_promote")]
    review = [item for item in suggestions if not item.get("auto_promote")]
    sections = [
        ("Auto-Applicable", auto),
        ("Needs Review", review),
    ]
    for title, items in sections:
        lines.append("")
        lines.append(_color(title, "\033[36m", stream=stream))
        if not items:
            lines.append("  none")
            continue
        for index, item in enumerate(items, start=1):
            lines.append(f"  {_format_suggestion_line(index, item, stream=stream)}")
    return "\n".join(lines)


def _review_suggestions_interactively(store, suggestions, input_func=input, stream=sys.stdout):
    approved = []
    skipped = []
    rejected = []
    quit_early = False
    for index, item in enumerate(suggestions, start=1):
        prompt = (
            f"{_format_suggestion_line(index, item, stream=stream)}\n"
            "Approve [a], skip [s], reject [r], or quit [q]? "
        )
        while True:
            choice = input_func(prompt).strip().lower()
            if choice in {"a", "approve"}:
                rule = dict(item["rule"])
                metadata = dict(rule.get("metadata", {}))
                metadata["promotion_state"] = "interactive-approved"
                applied = store.add_rule({**rule, "metadata": metadata})
                approved.append({**item, "applied": applied})
                break
            if choice in {"s", "skip", ""}:
                skipped.append(item)
                break
            if choice in {"r", "reject"}:
                rejected.append(item)
                break
            if choice in {"q", "quit"}:
                skipped.append(item)
                skipped.extend(suggestions[index:])
                quit_early = True
                break
            print("Enter a, s, r, or q.", file=stream)
        if quit_early:
            break
    store.replace_suggestions([item["rule"] for item in skipped])
    return {
        "approved": approved,
        "skipped": skipped,
        "rejected": rejected,
        "quit_early": quit_early,
    }


def _format_interactive_summary(result):
    return (
        f"interactive summary: approved {len(result['approved'])}, "
        f"skipped {len(result['skipped'])}, rejected {len(result['rejected'])}"
    )


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


def _upsert_delegate(config, delegate):
    delegates = list(config.get("delegates") or [])
    target_name = delegate.get("name")
    replaced = False
    retained = []
    for existing in delegates:
        if existing.get("name") == target_name:
            retained.append(dict(delegate))
            replaced = True
        else:
            retained.append(existing)
    if not replaced:
        retained.append(dict(delegate))
    config["delegates"] = retained
    return replaced


def _is_internal_review(review):
    tool = review.get("tool") or ""
    template = review.get("template") or ""
    raw = review.get("raw") or ""
    if tool in {"codex", "claude"}:
        return True
    if tool == "node" and ("codex" in raw or "approved-script" in template):
        return True
    if ".agent-jail/.codex/.tmp/plugins" in raw or ".agent-jail/.codex/.tmp/plugins" in template:
        return True
    if ".agent-jail/workspace" in raw or ".agent-jail/workspace" in template:
        return True
    return False


def _is_actionable_review(review):
    confidence = review.get("confidence")
    try:
        confidence_value = float(confidence) if confidence is not None else None
    except (TypeError, ValueError):
        confidence_value = None
    if confidence_value == 0.0:
        return False
    reason = (review.get("reason") or "").lower()
    if reason.startswith("jit provider unavailable:"):
        return False
    if reason.startswith("jit http error:"):
        return False
    if reason.startswith("jit request failed:"):
        return False
    if reason in {"jit response payload was not valid json", "jit response was not valid json"}:
        return False
    if review.get("decision_hint") == "reject":
        return False
    return True


def _review_sort_key(review):
    confidence = review.get("confidence")
    if confidence is None:
        confidence_value = -1.0
    else:
        confidence_value = float(confidence)
    return (_is_internal_review(review), -confidence_value, review.get("tool", ""), review.get("template", ""), review.get("id", ""))


def _colorize(text, color, enabled):
    if not enabled:
        return text
    return f"{color}{text}{ANSI_RESET}"


def _format_review_list(reviews, show_all=False, color=False):
    visible = sorted(reviews, key=_review_sort_key)
    if not show_all:
        visible = [review for review in visible if _is_actionable_review(review) and not _is_internal_review(review)]
    hidden_count = len(reviews) - len(visible)
    lines = [f"pending: {len(reviews)}"]
    if not visible:
        lines.append("no actionable pending reviews" if hidden_count else "none")
    for review in visible:
        template = review.get("template") or review.get("raw") or ""
        confidence = review.get("confidence")
        confidence_text = ""
        if confidence is not None:
            confidence_text = f" | conf={float(confidence):.2f}"
        source = review.get("source")
        source_text = f" | {source}" if source else ""
        header = f"- {review['id']} | {review.get('tool')} {review.get('action')} | {template}{confidence_text}{source_text}"
        header = _colorize(header, ANSI_DIM if _is_internal_review(review) else ANSI_YELLOW, color)
        lines.append(header)
        reason = review.get("reason")
        if reason:
            lines.append(f"  reason: {reason}")
    if hidden_count and not show_all:
        lines.append(_colorize(f"hidden internal reviews: {hidden_count} (use --all)", ANSI_DIM, color))
    return "\n".join(lines)


def handle_review(args):
    home = ensure_home()
    store = PolicyStore(os.path.join(home, "policy.json"))
    config_path = os.path.join(home, "config.json")
    if args.review_command == "list":
        reviews = store.pending_reviews
        if args.json:
            print(json.dumps(reviews, indent=2, sort_keys=True))
        else:
            print(_format_review_list(reviews, show_all=args.all, color=sys.stdout.isatty()))
        return 0
    review = store.get_pending_review(args.review_id)
    if not review:
        print(f"agent-jail review: unknown id {args.review_id}", file=sys.stderr)
        return 2
    if args.review_command == "approve":
        if review.get("kind") == "delegate-config":
            delegate = review.get("delegate") or {}
            if not delegate.get("name"):
                print(f"agent-jail review: pending delegate review {args.review_id} is missing delegate config", file=sys.stderr)
                return 2
            config = load_config(config_path)
            replaced = _upsert_delegate(config, delegate)
            save_config(config, config_path)
            store.remove_pending_review(args.review_id)
            print("already-approved" if replaced else "approved")
            return 0
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
    if args.proxy is not None:
        run_defaults["proxy"] = bool(args.proxy)
    if args.allow_ops is not None:
        run_defaults["allow_ops"] = bool(args.allow_ops)
    if args.allow_delegate:
        run_defaults["allow_delegates"] = sorted(set(args.allow_delegate))
    if args.project_mode is not None:
        run_defaults["project_mode"] = args.project_mode
    config.setdefault("defaults", {})
    config["defaults"]["run"] = run_defaults
    save_config(config, config_path)
    print(json.dumps(load_config(config_path), indent=2, sort_keys=True))
    return 0


def handle_network(args):
    home = ensure_home()
    store = PolicyStore(os.path.join(home, "policy.json"))
    if args.network_command == "list":
        rules = [rule for rule in store.rules if rule.get("kind") == "network"]
        if args.json:
            print(json.dumps(rules, indent=2, sort_keys=True))
            return 0
        if not rules:
            print("network rules: none")
            return 0
        print(f"network rules: {len(rules)}")
        for rule in rules:
            port = rule.get("port")
            scheme = rule.get("scheme") or "any"
            decision = "allow" if rule.get("allow") else "deny"
            suffix = f":{port}" if port is not None else ""
            print(f"- {decision} {rule.get('host')}{suffix} [{scheme}]")
        return 0
    if args.network_command == "test":
        policy = ProxyPolicy(store.rules, default_allow=not args.default_deny)
        verdict = policy.decide("CONNECT", args.host, args.port, scheme=args.scheme)
        print(json.dumps({"host": args.host, "port": args.port, "scheme": args.scheme, **verdict}, sort_keys=True))
        return 0
    rule = {
        "kind": "network",
        "host": args.host,
        "port": args.port,
        "scheme": args.scheme,
        "allow": args.network_command == "allow",
    }
    replaced = store.set_rule(rule)
    decision = "allow" if rule["allow"] else "deny"
    status = "updated" if replaced else "added"
    port = f":{args.port}" if args.port is not None else ""
    print(f"{status} {decision} {args.host}{port} [{args.scheme}]")
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
    if args.command == "network":
        return handle_network(args)
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
    proxy_enabled = run_defaults.get("proxy", True) if args.proxy is None else bool(args.proxy)
    with tempfile.TemporaryDirectory(prefix="agent-jail-") as tmp:
        source_root = os.path.dirname(os.path.dirname(__file__))
        python_executable = resolve_python()
        wrapper_dir = os.path.join(tmp, ".agent-jail", "bin")
        sock_path = os.path.join(tmp, "broker.sock")
        event_socket_path = os.path.join(tmp, "events.sock")
        runtime_session = f"session-{datetime.now(UTC).strftime('%Y%m%dT%H%M%S')}-{os.getpid()}"
        event_log_path = os.path.join(
            home,
            "events",
            f"{runtime_session}.jsonl",
        )
        session_state_path = runtime_state_record_path(home, runtime_session)
        store = PolicyStore(os.path.join(home, "policy.json"))
        delegate_names = set(run_defaults.get("allow_delegates", []))
        delegate_names.update(args.allow_delegate or [])
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
            read_only_roots=config.get("filesystem", {}).get("read_only_roots", []) + run_defaults.get("read_only_roots", []) + discover_auxiliary_read_roots(),
            write_roots=config.get("filesystem", {}).get("write_roots", []) + run_defaults.get("write_roots", []),
            skills_proxy=True,
            ops_exec=allow_ops,
            delegates=sorted(delegate_names),
            browser_automation=args.allow_browser,
            direct_secret_env=args.direct_secret_env,
        )
        event_sink = EventSink(event_log_path, socket_path=event_socket_path, default_fields={"session": runtime_session})
        event_sink.start()
        runtime_payload = {
            "active": True,
            "cwd": os.getcwd(),
            "events_log": event_log_path,
            "events_socket": event_socket_path,
            "pid": os.getpid(),
            "session": runtime_session,
            "started_at": datetime.now(UTC).isoformat(),
        }
        write_runtime_state(runtime_state_path(home), runtime_payload)
        write_runtime_state(session_state_path, runtime_payload)
        broker = BrokerServer(
            sock_path,
            store,
            capabilities=session["capabilities"],
            delegates=config.get("delegates", []),
            secrets=config.get("secrets", {}),
            mounts=session["mounts"] + [{"path": tmp, "mode": "rw"}],
            deny_read_patterns=config.get("filesystem", {}).get("deny_read_patterns", []),
            event_sink=event_sink,
            log_stderr=bool(os.environ.get("AGENT_JAIL_LOG_STDERR")),
            llm_policy=config.get("llm_policy", {}),
        )
        broker_thread = threading.Thread(target=broker.serve_forever, daemon=True)
        broker_thread.start()
        write_wrappers(wrapper_dir, source_path=os.environ.get("PATH", ""), python_executable=python_executable)
        cap_target = os.path.join(wrapper_dir, "agent-jail-cap")
        with open(cap_target, "w", encoding="utf-8") as handle:
            handle.write(render_cap_launcher(source_root, python_executable))
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
                "AGENT_JAIL_HOST_HOME": os.path.expanduser("~"),
                "HOME": home,
                "PATH": wrapper_dir + os.pathsep + env.get("PATH", ""),
                "PYTHONPATH": source_root + os.pathsep + env.get("PYTHONPATH", ""),
            }
        )
        cert_env = discover_macos_system_cert_env(tmp)
        if not cert_env:
            cert_env = discover_cert_env()
        for key, value in cert_env.items():
            env.setdefault(key, value)
        for key, value in discover_tty_env().items():
            env.setdefault(key, value)
        if kill_switch:
            env["AGENT_JAIL_KILL_SWITCH"] = kill_switch
        http_proxy_server = None
        socks_proxy_server = None
        session_proxy_env = {}
        if proxy_enabled:
            policy = ProxyPolicy(store.rules, default_allow=not args.deny_network_by_default)
            http_proxy_server, _ = start_http_proxy(policy, event_sink=event_sink, debug=args.proxy_debug)
            socks_proxy_server, _ = start_socks_proxy(policy, event_sink=event_sink, debug=args.proxy_debug)
            http_proxy_url = f"http://127.0.0.1:{http_proxy_server.server_port}"
            socks_proxy_url = f"socks5://127.0.0.1:{socks_proxy_server.server_address[1]}"
            env["AGENT_JAIL_HTTP_PROXY"] = http_proxy_url
            env["AGENT_JAIL_SOCKS_PROXY"] = socks_proxy_url
            proxy_mode = args.proxy_mode or "hybrid"
            if proxy_mode in {"http", "hybrid", "codex-http", "codex-http-native"}:
                env["HTTP_PROXY"] = http_proxy_url
                env["HTTPS_PROXY"] = http_proxy_url
            else:
                env.pop("HTTP_PROXY", None)
                env.pop("HTTPS_PROXY", None)
            if proxy_mode in {"socks", "hybrid"}:
                env["SOCKS_PROXY"] = socks_proxy_url
            else:
                env.pop("SOCKS_PROXY", None)
            if proxy_mode == "socks":
                env["ALL_PROXY"] = socks_proxy_url
            else:
                env.pop("ALL_PROXY", None)
            session_proxy_env = {
                key: env[key]
                for key in (
                    "HTTP_PROXY",
                    "HTTPS_PROXY",
                    "ALL_PROXY",
                    "SOCKS_PROXY",
                    "SSL_CERT_FILE",
                    "SSL_CERT_DIR",
                    "AGENT_JAIL_HTTP_PROXY",
                    "AGENT_JAIL_SOCKS_PROXY",
                )
                if key in env
            }
        backend = choose_backend(preferred=env.get("AGENT_JAIL_BACKEND"))
        try:
            target_argv = resolve_target(args.target, env)
        except FileNotFoundError as exc:
            print(f"agent-jail: target command not found: {exc}", file=sys.stderr)
            return 127
        if proxy_enabled and args.proxy_commands_only:
            session_proxy_env_path = os.path.join(tmp, "session-proxy-env.json")
            with open(session_proxy_env_path, "w", encoding="utf-8") as handle:
                json.dump(session_proxy_env, handle, sort_keys=True)
            bootstrap_hops = 2 if args.target and os.path.basename(args.target[0]) == "codex" else 1
            env["AGENT_JAIL_PROXY_BYPASS_WRAPPER_HOPS"] = str(bootstrap_hops)
            for key in (
                "AGENT_JAIL_HTTP_PROXY",
                "AGENT_JAIL_SOCKS_PROXY",
                "HTTP_PROXY",
                "HTTPS_PROXY",
                "ALL_PROXY",
                "SOCKS_PROXY",
                "http_proxy",
                "https_proxy",
                "all_proxy",
                "socks_proxy",
                "SSL_CERT_FILE",
                "SSL_CERT_DIR",
                "REQUESTS_CA_BUNDLE",
                "CURL_CA_BUNDLE",
                "NODE_EXTRA_CA_CERTS",
            ):
                env.pop(key, None)
        apply_target_env_profile(env, target_argv, proxy_mode=args.proxy_mode if proxy_enabled else None)
        if args.print_launch_env:
            print(
                json.dumps(
                    {
                        key: env.get(key)
                        for key in sorted(
                            {
                                "HTTP_PROXY",
                                "HTTPS_PROXY",
                                "ALL_PROXY",
                                "SOCKS_PROXY",
                                "SSL_CERT_FILE",
                                "SSL_CERT_DIR",
                                "REQUESTS_CA_BUNDLE",
                                "CURL_CA_BUNDLE",
                                "NODE_EXTRA_CA_CERTS",
                                "http_proxy",
                                "https_proxy",
                                "all_proxy",
                                "socks_proxy",
                                "AGENT_JAIL_HTTP_PROXY",
                                "AGENT_JAIL_SOCKS_PROXY",
                                "AGENT_JAIL_SESSION_PROXY_ENV",
                            }
                        )
                        if key in env
                    },
                    indent=2,
                    sort_keys=True,
                ),
                file=sys.stderr,
                flush=True,
            )
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
            if http_proxy_server:
                http_proxy_server.shutdown()
                http_proxy_server.server_close()
            if socks_proxy_server:
                socks_proxy_server.shutdown()
                socks_proxy_server.server_close()
            broker.close()
            event_sink.close()
            final_payload = {
                "active": False,
                "cwd": os.getcwd(),
                "events_log": event_log_path,
                "events_socket": None,
                "ended_at": datetime.now(UTC).isoformat(),
                "pid": os.getpid(),
                "session": runtime_session,
                "started_at": runtime_payload["started_at"],
            }
            write_runtime_state(runtime_state_path(home), final_payload)
            write_runtime_state(session_state_path, final_payload)


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
