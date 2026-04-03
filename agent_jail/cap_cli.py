import argparse
import json
import os
import sys

from agent_jail.broker import broker_request
from agent_jail.broker import broker_exchange
from agent_jail.broker import CAPABILITY_CLIENT_KIND


def _kill_switch_triggered():
    path = os.environ.get("AGENT_JAIL_KILL_SWITCH")
    return bool(path) and os.path.exists(path)


def parse_args(argv=None):
    parser = argparse.ArgumentParser(prog="agent-jail-cap")
    sub = parser.add_subparsers(dest="command", required=True)

    delegate = sub.add_parser("delegate")
    delegate.add_argument("name")
    delegate.add_argument("argv", nargs=argparse.REMAINDER)

    ops = sub.add_parser("ops")
    ops.add_argument("argv", nargs=argparse.REMAINDER)

    skill = sub.add_parser("skill")
    skill.add_argument("name")
    skill.add_argument("operation")

    browser = sub.add_parser("browser")
    browser.add_argument("tool")
    browser.add_argument("action")

    return parser.parse_args(argv)


def _request(payload):
    if _kill_switch_triggered():
        print("agent-jail-cap stopped by kill switch", file=sys.stderr)
        raise SystemExit(125)
    sock_path = os.environ.get("AGENT_JAIL_SOCKET")
    if not sock_path:
        raise SystemExit("agent-jail-cap requires AGENT_JAIL_SOCKET")
    payload = {**payload, "client": CAPABILITY_CLIENT_KIND}
    reply = broker_request(sock_path, payload)
    if reply["decision"] != "allow":
        print(f"agent-jail-cap denied: {reply['reason']}", file=sys.stderr)
        raise SystemExit(126)
    print(json.dumps(reply["result"], sort_keys=True))
    return 0


def _request_delegate_stream(payload):
    if _kill_switch_triggered():
        print("agent-jail-cap stopped by kill switch", file=sys.stderr)
        raise SystemExit(125)
    sock_path = os.environ.get("AGENT_JAIL_SOCKET")
    if not sock_path:
        raise SystemExit("agent-jail-cap requires AGENT_JAIL_SOCKET")
    payload = {**payload, "client": CAPABILITY_CLIENT_KIND}
    frames = broker_exchange(sock_path, payload)
    first = next(frames)
    if first["decision"] != "allow":
        print(f"agent-jail-cap denied: {first['reason']}", file=sys.stderr)
        raise SystemExit(126)
    if not first.get("stream"):
        print(json.dumps(first["result"], sort_keys=True))
        return 0
    returncode = 0
    for frame in frames:
        frame_type = frame.get("type")
        if frame_type in {"header", "data"}:
            target = sys.stdout if frame.get("stream") == "stdout" else sys.stderr
            target.write(frame.get("text", ""))
            target.flush()
        elif frame_type == "exit":
            returncode = int(frame.get("returncode", 1))
            break
    return returncode


def main(argv=None):
    args = parse_args(argv)
    if args.command == "delegate":
        return _request_delegate_stream({"type": "capability", "name": "delegate", "payload": {"name": args.name, "command": args.argv, "cwd": os.getcwd()}})
    if args.command == "ops":
        return _request_delegate_stream({"type": "capability", "name": "delegate", "payload": {"name": "ops", "command": args.argv, "cwd": os.getcwd()}})
    if args.command == "skill":
        return _request(
            {
                "type": "capability",
                "name": "skills_proxy",
                "payload": {"name": args.name, "operation": args.operation},
            }
        )
    return _request(
        {
            "type": "capability",
            "name": "browser_automation",
            "payload": {"tool": args.tool, "action": args.action},
        }
    )


if __name__ == "__main__":
    raise SystemExit(main())
