# agent-jail

`agent-jail` is a lightweight brokered runtime for AI agent CLIs such as `codex` and `claude`.

It is not a full sandbox. The primary goal is to reduce accidental damage by:

- intercepting commands through a wrapper layer
- classifying intent and risk
- allowing, denying, or auto-approving with logging
- learning reusable rules
- optionally routing network traffic through a policy-aware proxy
- separating direct project access from proxied sensitive capabilities

## Platform model

- Linux: prefers `bubblewrap`, then `proot`, with host fallback
- macOS: prefers `sandbox-exec`, then `alcless`, then host fallback

Backend selection controls filesystem/path behavior. Sensitive operations should still be proxied instead of passed through directly.

## Capability model

`agent-jail` separates direct access from mediated access.

Typical direct resources:

- selected project directories
- read-only local docs, prompts, and templates

Typical proxied resources:

- secret-bearing skills
- production control-plane commands
- browser and UI automation

This keeps the agent useful without handing it your full host environment.

## Usage

Run an agent under `agent-jail`:

```bash
python3 agent-jail run codex --yolo
python3 agent-jail run claude
```

Run with explicit project mapping and capability flags:

```bash
python3 agent-jail run \
  --project ~/workspace \
  --project ~/build/example-ops \
  --allow-write ~/build/agent-jail \
  --allow-ops \
  --allow-delegate ops \
  --allow-browser \
  codex --yolo
```

Use the mediated capability command surface inside a session:

```bash
python3 agent-jail run --allow-delegate ops agent-jail-cap delegate ops opsctl status
python3 agent-jail run --allow-ops agent-jail-cap ops opsctl status
python3 agent-jail run --allow-browser agent-jail-cap browser peekaboo screenshot
python3 agent-jail run agent-jail-cap skill gmail search
```

When a configured delegate runs in `mode: "execute"`, `agent-jail-cap delegate ...` behaves like a normal process:

- it prints a one-line delegate header to stderr
- it streams delegated stdout and stderr directly
- it exits with the delegated command's real return code

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

The session also resolves capabilities:

- project mounts are mapped read-only or read-write
- `skills_proxy` is enabled by default
- delegates are opt-in by name
- `ops_exec` remains as a backward-compatible alias for delegate `ops`
- `browser_automation` is opt-in
- direct secret env passthrough is off by default

Inside the session, proxied capabilities are exposed through `agent-jail-cap` instead of handing the agent raw host tools.

On macOS, the default `sandbox-exec` backend is a stopgap write-containment layer:

- it constrains writes to the selected writable project paths
- it keeps auth state and jail state writable where needed
- it applies to absolute-path shell launches like `/bin/zsh -lc ...`
- it is still deprecated Apple technology, so treat it as a practical guard rail rather than a future-proof sandbox

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

Capability rules can also be stored in the same policy file, for example:

- `skills_proxy`
- `ops_exec`
- `browser_automation`

## Network proxy

The proxy is explicit-proxy based. When enabled, `agent-jail` sets:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`

The proxy can allow or deny requests by host and port using network rules from the same policy file.

Limit:

- clients that ignore proxy environment variables are not covered

## Working with secrets, ops, and browsers

The intended pattern is:

- mount repos directly only when needed
- proxy secret-bearing skills instead of exposing raw env vars
- proxy production operations instead of giving the sandbox direct credentials
- proxy browser automation from the host side

The mediated command surface is:

- `agent-jail-cap delegate <name> ...`
- `agent-jail-cap ops ...` as a backward-compatible alias for delegate `ops`
- `agent-jail-cap skill <name> <operation>`
- `agent-jail-cap browser <tool> <action>`

Delegates are configured in:

```bash
~/.agent-jail/config.json
```

Example:

```json
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "~/build/**/.env",
      "~/build/**/.env.*",
      "~/build/**/secrets/**"
    ]
  },
  "delegates": [
    {
      "name": "ops",
      "run_as_user": "delegate-runner",
      "executor": "/usr/local/bin/delegate-exec",
      "allowed_tools": ["opsctl", "deployctl"],
      "strip_tool_name": true
    }
  ]
}
```

Use `strip_tool_name: true` when the delegate executor is already a tool-specific wrapper and expects only the subcommand argv after the tool name.

The optional `filesystem` section lets you widen read-only visibility and add extra writable roots without exposing your entire home directory. `deny_read_patterns` are expanded from your local home and rendered into the macOS `sandbox-exec` profile as explicit read denials, so broad read-only roots like `~/build` can still exclude secret-like files.

Sensitive tools are intended to be mediated-only. Direct execution is blocked for:

- any tool listed in a configured delegate's `allowed_tools`
- `peekaboo`
- `playwright-cli`
- `screencog`
- `sudo`
- any configured delegate executor

Use `agent-jail-cap delegate ...`, `agent-jail-cap ops ...`, or `agent-jail-cap browser ...` instead.

This is especially important for:

- local operations repositories
- browser UI automation tools
- any skill that depends on API keys or personal account access

The jail also adds a small compatibility layer for agent sessions:

- `python` is shimmed to the resolved host Python executable
- `~/build` and `~/workspace` inside the jail point back to the real home directories when present
- on macOS, the active controlling terminal paths are exposed to the `sandbox-exec` profile for interactive TUI startup

## Known limits

- Absolute-path shell invocation such as `/bin/zsh -lc ...` is not fully blocked by `PATH` interception alone.
- macOS `sandbox-exec` improves the `/bin/zsh -lc ...` gap by constraining the process tree, but it is deprecated and should be treated as a stopgap.
- `alcless` on macOS improves separation but does not give the same absolute-path guarantees as a rootfs-based backend.
- Linux containment depends on local availability of `bubblewrap` or `proot`.
- Sensitive capabilities are only protected when they are actually proxied rather than mounted or passed through directly.
- This tool is designed for containment of ordinary agent mistakes, not hostile code execution.
