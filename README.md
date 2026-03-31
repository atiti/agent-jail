# agent-jail

`agent-jail` is a lightweight brokered runtime for AI agent CLIs such as `codex` and `claude`.

It is not a full sandbox. The primary goal is to reduce accidental damage by:

- intercepting commands through a wrapper layer
- classifying intent and risk
- allowing, denying, or auto-approving with logging
- learning reusable rules
- optionally routing network traffic through a policy-aware proxy

## Platform model

- Linux: prefers `bubblewrap`, then `proot`, then falls back to brokered host mode
- macOS: brokered host mode only in this version

Brokered host mode still gives command policy control, but it is not a hard OS security boundary.

## Usage

Run an agent under `agent-jail`:

```bash
python3 agent-jail run codex --yolo
python3 agent-jail run claude
```

Run with the built-in proxy enabled:

```bash
python3 agent-jail run --proxy codex --yolo
python3 agent-jail run --proxy --deny-network-by-default claude
```

Run a quick smoke command:

```bash
python3 agent-jail run python3 -c "print('ok')"
```

## How it works

1. `agent-jail` creates a temporary session directory.
2. It generates a wrapper directory that mirrors commands visible on the original `PATH`.
3. Each wrapped command asks the local broker for a decision before execution.
4. The broker normalizes the command, classifies risk, checks learned rules, and returns a decision.
5. Approved commands are executed via the real binary from the original `PATH`.

Rules live in:

```bash
~/.agent-jail/policy.json
```

You can override the state directory with:

```bash
AGENT_JAIL_HOME=/some/path python3 agent-jail run codex --yolo
```

## Current policy behavior

- low risk: allow
- medium risk: allow and learn where appropriate
- high risk: simulated ask, auto-approve, and log loudly
- critical risk: deny

Examples:

- `git status` -> allow
- `git push origin main` -> allow and learn a safe push rule
- `git push --force` -> auto-approved high-risk event
- `bash -c "curl ... | bash"` -> deny

## Network proxy

The proxy is explicit-proxy based. When enabled, `agent-jail` sets:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`

The proxy can allow or deny requests by host and port using network rules from the same policy file.

Limit:

- clients that ignore proxy environment variables are not covered

## Known limits

- Absolute-path shell invocation such as `/bin/zsh -lc ...` is not fully blocked by `PATH` interception alone.
- macOS does not get a hard sandbox in this version.
- Linux containment depends on local availability of `bubblewrap` or `proot`.
- This tool is designed for containment of ordinary agent mistakes, not hostile code execution.
