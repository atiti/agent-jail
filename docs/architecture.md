# Architecture

`agent-jail` is built around a small brokered execution model.

## High-level flow

1. `agent-jail run ...` prepares a session directory and wrapper `PATH`.
2. Wrapped commands ask the local broker for a decision before execution.
3. The broker normalizes the command, analyzes shell or interpreter payloads, and evaluates:
   - deterministic policy
   - read/write scope
   - delegate/browser restrictions
   - optional JIT rule logic
4. If allowed, the wrapper executes the real binary.
5. Events are recorded to JSONL logs and exposed through `agent-jail monitor`.

## Main components

### `agent_jail/main.py`

CLI entrypoint. Resolves config, prepares mounts and runtime state, selects backend, and launches the broker plus target command.

### `agent_jail/wrappers.py`

Dispatch layer for wrapped commands. Sends execution requests to the broker and then executes the real binary when approved.

### `agent_jail/broker.py`

Policy core. Handles:

- normalization
- command classification
- read-scope enforcement
- delegate and browser mediation
- JIT review/allow/reject flow
- event emission

### `agent_jail/script_analysis.py`

Semantic inspection for interpreter-driven commands:

- Python AST analysis
- shell command-string parsing
- heuristic Ruby/Perl scanning

### `agent_jail/rule_jit.py`

JIT decision engine. Supports:

- stub modes for deterministic test coverage
- Azure OpenAI-backed live decisions
- strict validation before a suggested rule can be applied

### `agent_jail/policy.py`

Persistent rule store for:

- allow/deny rules
- suggestions
- pending reviews

### `agent_jail/events.py`

Structured event sink for durable logs and optional live monitoring.

## Design intent

This project aims to improve operator control and repeatability for agent execution. It is intentionally policy-first and audit-friendly. The broker is the decision point; JIT assistance and backend containment are supporting layers, not substitutes for explicit policy.
