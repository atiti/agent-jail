# agent-jail

[![Python](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/platform-macOS%20%7C%20Linux-6f42c1.svg)](#platform-model)
[![Tests](https://img.shields.io/badge/tests-unittest-green.svg)](#verification)

`agent-jail` is a brokered runtime for agent CLIs such as `codex` and `claude`.

It sits between an agent and the host shell, intercepts commands, applies policy, and gives you a cleaner capability boundary than "let the model run directly on my machine".

`agent-jail` is not a formal security sandbox. It is an operator-control layer designed to:

- intercept commands through a wrapper layer
- classify intent and risk
- allow, deny, or route commands through mediated capability bridges
- learn reusable rules from repeated low-risk behavior
- keep logs and reviewable policy state
- optionally route network traffic through a policy-aware proxy

## What it is good for

- letting an agent work directly inside selected repos without handing it your full host
- forcing production or secret-bearing actions through delegates instead of raw tools
- making policy decisions observable and repeatable
- pressure-testing agent behavior with deterministic and JIT-backed manual suites

## What it is not

- not a VM
- not a container manager
- not a guarantee against a determined local attacker
- not a substitute for host hardening, credential hygiene, or environment separation

## Quick start

Run an agent inside a brokered session:

```bash
python3 agent-jail run codex --help
python3 agent-jail run claude --help
```

Run with an explicit writable project:

```bash
python3 agent-jail run \
  --project ~/build/my-repo \
  --allow-write ~/build/my-repo \
  codex exec "List the repo and summarize it"
```

Watch events in another terminal:

```bash
python3 agent-jail monitor --follow
```

Run the built-in validation suites:

```bash
python3 -m unittest discover -s tests -v
bash scripts/manual_policy_suite.sh --mode deterministic
bash scripts/manual_policy_suite.sh --mode jit
```

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

Inspect agent-jail events without polluting the agent TUI:

```bash
python3 agent-jail monitor
python3 agent-jail monitor --follow
python3 agent-jail monitor --json
```

Generate policy suggestions from observed event history:

```bash
python3 agent-jail suggest-rules
python3 agent-jail suggest-rules --apply-low-risk
python3 agent-jail suggest-rules --json
```

Handle pending JIT reviews:

```bash
python3 agent-jail review list
python3 agent-jail review approve <id>
python3 agent-jail review reject <id>
```

Run the manual edge-case validation suite:

```bash
bash scripts/manual_policy_suite.sh --list
bash scripts/manual_policy_suite.sh
bash scripts/manual_policy_suite.sh --mode jit
bash scripts/manual_policy_suite.sh --mode live-azure
bash scripts/manual_policy_suite.sh --mode live-azure-all
```

## Verification

Unit tests:

```bash
python3 -m unittest discover -s tests -v
```

Manual policy validation:

```bash
bash scripts/manual_policy_suite.sh --mode deterministic
bash scripts/manual_policy_suite.sh --mode jit
```

Real Azure-backed JIT smoke / matrix:

```bash
export AZURE_OPENAI_ENDPOINT='https://...openai.azure.com'
export AZURE_OPENAI_API_KEY='...'
export AZURE_OPENAI_DEPLOYMENT='...'
export AZURE_OPENAI_JIT_TIMEOUT_MS=10000
bash scripts/manual_policy_suite.sh --mode live-azure-all
```

## How it works

1. `agent-jail` creates a temporary session directory.
2. It generates a wrapper directory that mirrors commands visible on the original `PATH`.
3. Each wrapped command asks the local broker for a decision before execution.
4. The broker normalizes the command, classifies risk, checks learned rules, and returns a decision.
5. Approved commands are executed via the real binary from the original `PATH`.

Broker decisions are recorded as structured JSONL events under `~/.agent-jail/events/`. The latest session also publishes its event log and optional live socket in `~/.agent-jail/runtime.json`, which powers `agent-jail monitor`.

Those same event logs power `agent-jail suggest-rules`, which clusters repeated command patterns and can propose broader allow rules without widening to path-specific one-offs.

For common interpreters, the broker now reasons about script payloads instead of only the outer launcher command:

- `sandbox-exec -f ... python3 -c ...` is analyzed as a Python script invocation, not `sandbox-exec *`
- `python3 -c ...` and local `.py` files get Python-specific static analysis
- `sh` / `bash` / `zsh` command strings and local shell scripts are summarized semantically
- `ruby` and `perl` get conservative heuristic scanning

This keeps pending reviews and learned rules focused on semantic templates such as `python read-only subprocess script` instead of backend wrapper noise.

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

Set `AGENT_JAIL_LOG_STDERR=1` if you want the broker to keep mirroring events to stderr. By default, event output is written to the session event log instead, which keeps interactive TUIs clean.

## Current policy behavior

- low risk: allow
- medium risk: allow and learn where appropriate
- high risk: simulated ask, auto-approve, and log loudly
- critical risk: deny

Examples:

- `git status` -> allow
- `git push origin main` -> allow and learn a safe push rule
- `git push --force` -> auto-approved high-risk event
- `rm -rf agent_jail/__pycache__ tests/__pycache__` -> allow when all targets are repo-local generated artifacts
- `bash -c "curl ... | bash"` -> deny

Capability rules can also be stored in the same policy file, for example:

- `skills_proxy`
- `ops_exec`
- `browser_automation`

For shell command strings such as `bash -c "..."`, `agent-jail` now analyzes chained segments, pipelines, subshells, and command substitutions for policy before execution. The original shell string is still executed unchanged if it passes.

Interpreter-driven commands use the same idea: payloads are inspected for risk and generalized into semantic templates, but the original command line is still what executes if policy allows it.

## Network proxy

The proxy is explicit-proxy based. When enabled, `agent-jail` sets:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `ALL_PROXY`

The proxy can allow or deny requests by host and port using network rules from the same policy file.

Limit:

- clients that ignore proxy environment variables are not covered

## Repository health

- [Contributing guide](/Users/attilasukosd/build/agent-jail/CONTRIBUTING.md)
- [Security policy](/Users/attilasukosd/build/agent-jail/SECURITY.md)
- [Support guide](/Users/attilasukosd/build/agent-jail/SUPPORT.md)
- [Code of conduct](/Users/attilasukosd/build/agent-jail/CODE_OF_CONDUCT.md)

## Project status

This project is usable, but still evolving. Expect policy and test coverage to improve faster than backend isolation guarantees.

Recommended reading:

- [docs/manual-policy-suite.md](/Users/attilasukosd/build/agent-jail/docs/manual-policy-suite.md)
- [2026-03-31-agent-jail-design.md](/Users/attilasukosd/build/agent-jail/docs/superpowers/specs/2026-03-31-agent-jail-design.md)
- [2026-03-31-agent-jail-lifestyle-design.md](/Users/attilasukosd/build/agent-jail/docs/superpowers/specs/2026-03-31-agent-jail-lifestyle-design.md)

## Open source notes

- No license file has been added in this pass.
- Repository-specific or private environment assumptions should stay in local config, not in tracked files.

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

The broker also enforces read scope for explicit file targets. A command can still be low-risk in general and be denied if it tries to read outside the configured project and read-only roots. For example, `cat README.md` in a mounted repo can pass while `cat /etc/passwd` is denied.

You can also configure Azure OpenAI for offline rule suggestion and low-risk auto-promotion:

```json
{
  "llm_policy": {
    "provider": "azure_openai",
    "model": "gpt-5.4",
    "endpoint_env": "AZURE_OPENAI_ENDPOINT",
    "api_key_env": "AZURE_OPENAI_API_KEY",
    "deployment_env": "AZURE_OPENAI_DEPLOYMENT",
    "api_version": "2024-10-21",
    "auto_promote_min_count": 3,
    "confidence_threshold": 0.8
  }
}
```

When configured, `agent-jail suggest-rules` asks Azure OpenAI for generalized proposals, validates them deterministically, and only auto-applies low-risk rules that clear the configured thresholds.

You can also enable a narrow JIT rule lane for unknown low-impact commands:

```json
{
  "llm_policy": {
    "provider": "azure_openai",
    "jit_enabled": true,
    "jit_timeout_ms": 800,
    "jit_auto_apply_low_risk": true,
    "confidence_threshold": 0.8
  }
}
```

This JIT path only applies to commands that currently fall through to low-risk `general`. Known read-only tools and deterministic heuristics still resolve locally. If the JIT engine is confident, it can auto-apply a generalized low-risk rule immediately. If it is unsure, the command is denied with a review-required reason instead of being silently widened.

Those review-required cases are written into `policy.json` as pending reviews. Approving one will install the proposed rule so the next matching command is allowed without another prompt.

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
