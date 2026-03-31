# Agent-Jail Lifestyle Improvements Design

Date: 2026-03-31
Status: Proposed

## Goal

Improve `agent-jail` for daily use without making the project organization-specific. The design covers five coordinated slices:

1. config-driven read and write policy for `~/workspace` and `~/build`
2. delegate bridge passthrough that behaves like the original command
3. shell-command safety analysis for chained commands without rewriting execution
4. TUI-safe broker event transport and monitoring
5. LLM-assisted policy suggestion and low-risk auto-learning

## Non-Goals

- rewriting user or model shell commands before execution
- embedding organization-specific delegated tools or runner names in the core policy engine
- allowing auto-learned rules for privilege escalation, secret access, networking exceptions, or destructive commands
- replacing deterministic policy evaluation with LLM decisions at runtime

## Design Overview

`agent-jail` keeps deterministic enforcement in the broker and sandbox backend. It gains:

- config-driven mount and read policy overlays
- delegate commands that stream output and preserve exit codes
- structured command parsing for analysis only
- durable event logging with optional live monitoring
- offline or asynchronous rule suggestion using Azure OpenAI

Execution remains compatible-first:

- preserve the original command string
- preserve stdout and stderr semantics
- preserve exit codes
- only deny before launch when policy determines the command is unsafe

## 1. Config-Driven Mount And Read Policy

### Requirements

- `~/workspace` should be writable by default for this setup
- the active project root should remain writable
- `~/build` should be recursively readable
- read access inside `~/build` must exclude secret-like files and directories from local config
- the feature must remain generic enough for open source

### Config Model

Add a local-policy layer in `~/.agent-jail/config.json`:

```json
{
  "filesystem": {
    "read_only_roots": ["~/build"],
    "write_roots": ["~/workspace"],
    "deny_read_patterns": [
      "**/.env",
      "**/.env.*",
      "**/*.pem",
      "**/*.key",
      "**/*.p12",
      "**/*.pfx",
      "**/secrets/**"
    ]
  }
}
```

### Behavior

- `write_roots` are merged with the session project root and explicit `--allow-write` paths
- `read_only_roots` are exposed to the sandbox as globally readable areas
- `deny_read_patterns` override broader read access and are checked by the broker before allowing sensitive file reads
- path expansion uses the real host home directory before jail remapping

### Implementation Notes

- `config.py` should parse and normalize the filesystem section
- `main.py` should merge configured roots into the session environment
- `backend.py` should incorporate read-only roots into sandbox profile generation
- the broker should perform a second-pass deny on secret patterns so policy is still enforced even when the backend is coarse-grained

## 2. Delegate Passthrough UX

### Requirements

- `agent-jail-cap delegate ...` should behave like a normal process
- the delegated command's stdout and stderr should stream directly back
- the exit code should match the delegated command exactly
- a small prefix/header is acceptable
- broker transport can remain structured internally

### Behavior

CLI behavior:

```text
[delegate:ops] sudo -n -u delegate-runner /usr/local/bin/delegate-exec status .
<delegated stdout/stderr follows unchanged>
```

- the header is printed once to stderr
- stdout is passed through unchanged
- stderr is passed through unchanged after the header
- the CLI exits with the delegated command's exit code

### Implementation Notes

- `delegate_proxy.py` should support streaming subprocess I/O instead of `capture_output=True`
- `cap_cli.py` should stop printing JSON envelopes for successful delegate runs
- the broker should still use structured replies internally, but with a delegate result mode that lets the CLI become a passthrough wrapper

## 3. Shell Analysis Without Rewriting Execution

### Requirements

- preserve the original shell command string
- inspect chained commands, pipelines, subshells, and logical operators for policy
- classify both the overall command and its parts
- deny if any part is unsafe or if the combination is unsafe

### Design

Introduce a shell analysis module that parses commands into:

- original raw command
- segments split by `&&`, `||`, `;`, and pipelines
- nested subshells and command substitutions
- discovered tool invocations and absolute paths

The broker evaluates:

1. holistic command risk
2. per-segment risk
3. special combination rules

Examples:

- `cat foo | rg bar && sed -n 1,10p file`
  - likely low risk if all inputs are readable
- `cat foo | curl ... | sh`
  - deny because the full pattern is remote execution
- `safe_cmd && sudo something`
  - deny because one segment is privilege escalation

### Implementation Notes

- keep using the original command string for execution if it passes
- use parsing only for policy classification
- start with a conservative parser that covers common shell control operators and command substitutions
- when parsing is ambiguous, fail closed for high-risk constructs

## 4. TUI-Safe Event Transport

### Requirements

- broker policy logs should stop polluting the Codex TUI
- events should remain observable in real time
- there should be a durable source of truth

### Design

Use two layers:

- append-only structured event log file as the canonical record
- optional Unix domain socket broadcast for live subscribers

Event record fields:

- timestamp
- event type
- decision
- command raw string
- normalized template
- category
- capability or delegate metadata
- pid/session metadata

### UX

Add:

- `agent-jail monitor` to tail and format recent events
- optional `--json` monitor mode

Broker behavior:

- minimal stderr output in interactive TUI mode
- full stderr logging can remain available for non-interactive or debug mode

### Implementation Notes

- event file location should default under `~/.agent-jail/events/`
- socket should be best-effort and non-blocking
- the broker must never block command execution on monitor subscribers

## 5. LLM-Assisted Rule Suggestion With Azure OpenAI

### Requirements

- use Azure OpenAI first
- allow low-risk rules to auto-promote after repeated evidence
- generalize rules so they are broad enough to be useful, but not dangerously broad
- keep deterministic enforcement in the broker

### Design

This is an offline or asynchronous suggestion pipeline, not an in-band runtime decision maker.

Inputs:

- event log history
- normalized command templates
- current policy
- rule hit rates and override history

Outputs:

- candidate rule proposals
- confidence and rationale
- generalization level
- promotion recommendation

### Rule Promotion States

- `observed`
- `suggested`
- `auto-approved`
- `user-approved`
- `rejected`

### Auto-Promotion Guardrails

Only auto-promote low-risk patterns when:

- the pattern is observed repeatedly
- the normalized template is general enough to be useful
- there is no secret-path access
- there is no privilege escalation
- there is no remote execution or shell download
- there is no destructive tool use

Examples:

- good: `ls *`
- good: `git rev-parse *`
- bad: `ls build/dist/out/test.bin`
- bad: `cat secrets/prod.env`
- bad: `curl ... | sh`

### Azure OpenAI Integration

Use Azure OpenAI as the initial suggestion backend through a small adapter configured by environment or config:

```json
{
  "llm_policy": {
    "provider": "azure_openai",
    "model": "gpt-5.4",
    "endpoint_env": "AZURE_OPENAI_ENDPOINT",
    "api_key_env": "AZURE_OPENAI_API_KEY",
    "deployment_env": "AZURE_OPENAI_DEPLOYMENT"
  }
}
```

The adapter should:

- accept batches of normalized events
- request generalized candidate rules
- return structured JSON only
- never directly mutate policy without deterministic validation

## Phasing

Implement in this order:

1. mount and read policy
2. delegate passthrough UX
3. shell analysis without rewriting
4. TUI-safe event transport
5. Azure-backed rule suggestion pipeline

This order reduces risk because it first fixes core usability and policy visibility before adding learning behavior.

## Testing Strategy

Add tests for each slice:

- filesystem config parsing and root merging
- deny overlays for secret-pattern reads
- delegate stdout/stderr passthrough and exit-code preservation
- shell parsing and segment classification across `&&`, `||`, `;`, `|`, and `$(...)`
- event file persistence and live monitor broadcast
- rule normalization and guarded auto-promotion

Also add end-to-end tests for:

- reading across `~/build` while blocking configured secret paths
- delegated `opsctl` or `deployctl` style commands preserving output shape
- chained shell commands denied when one segment is unsafe

## Risks

- shell parsing can become too permissive if it tries to be clever
- deny overlays can produce confusing false positives without good event visibility
- live event streaming can deadlock the broker if implemented synchronously
- auto-generalization can become too broad without strong validation rules

## Recommendation

Proceed with the five slices in order, using Azure OpenAI only for suggestion and generalization, never for final runtime enforcement.
