# Interpreter Payload Analysis Design

Date: 2026-04-01
Status: Proposed

## Goal

Make `agent-jail` reason about the behavior of interpreter-driven commands instead of generating policy for launcher noise such as `sandbox-exec *` or blindly treating `python3 -c ...` as an opaque executable.

## Scope

Phase 1 adds static and heuristic analysis for common interpreter families:

- Python
- sh / bash / zsh
- Ruby
- Perl

It also unwraps launcher commands when the underlying executed command is still visible in argv, with `sandbox-exec` as the primary case on macOS.

## Requirements

- JIT and pending reviews must target semantic script behavior, not launcher wrappers.
- The broker must preserve the original command line for execution.
- Approved rules for interpreted scripts must match future semantically equivalent runs.
- Static analysis must remain conservative.

## Design

### 1. Launcher Unwrapping

When the broker sees a known launcher wrapper, it should derive an effective command subject before classification and JIT evaluation.

Initial support:

- `sandbox-exec -f <profile> <cmd> ...`

The raw command string remains unchanged for logging, but the broker reasons about `<cmd> ...`.

### 2. Semantic Templates

Interpreted commands gain a semantic template stored on the intent subject, for example:

- `python read-only subprocess script`
- `python local inspection script`
- `shell read-only script`
- `ruby subprocess script`

JIT prompts, pending reviews, and approved rules should all use this template.

### 3. Policy Matching

When a semantic template exists, approved rules should bind to it with a normal exact-match constraint:

```json
{
  "tool": "python3",
  "action": "exec",
  "constraints": {
    "template": "python read-only subprocess script"
  }
}
```

This keeps rules narrow enough to be safe while still useful across repeated script executions.

### 4. Static Analysis

#### Python

For `-c` payloads and readable local `.py` files:

- parse with `ast`
- inspect imports and function calls
- detect subprocess usage, shell execution, file writes, deletion, and common network libraries

Conservative categories:

- local inspection script
- read-only subprocess script
- mutating script
- network script
- dynamic script

#### Shell

For `sh -c`, `bash -c`, `zsh -c`, and readable local shell scripts:

- reuse the shell parser
- summarize the leaf commands
- distinguish read-only, cleanup, and mutating patterns

#### Ruby / Perl

Use heuristic scanning for:

- subprocess/system execution
- shell escapes
- file writes/deletes
- network clients

## Non-Goals

- fully emulating interpreter semantics
- auto-allowing broad `python3 *` or `bash *` rules
- treating dynamic code execution as low risk

## Success Criteria

- `agent-jail review list` no longer shows `sandbox-exec *` for interpreter-driven commands
- repeated `python3 -c ...` inspection scripts dedupe correctly by semantic template
- approving one pending review makes future equivalent script runs match that approved rule
