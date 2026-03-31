import argparse
import json
import os
import sys

from agent_jail.broker import broker_request


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
    reply = broker_request(sock_path, payload)
    if reply["decision"] != "allow":
        print(f"agent-jail-cap denied: {reply['reason']}", file=sys.stderr)
        raise SystemExit(126)
    print(json.dumps(reply["result"], sort_keys=True))
    return 0


def main(argv=None):
    args = parse_args(argv)
    if args.command == "delegate":
        return _request({"type": "capability", "name": "delegate", "payload": {"name": args.name, "command": args.argv}})
    if args.command == "ops":
        return _request({"type": "capability", "name": "delegate", "payload": {"name": "ops", "command": args.argv}})
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
