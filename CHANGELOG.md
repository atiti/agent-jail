# Changelog

## Unreleased

- Added the initial `agent-jail` CLI launcher.
- Added command interception through generated PATH wrappers and a local broker.
- Added command normalization, risk classification, allow/deny decisions, and rule learning.
- Added backend selection for Linux `bubblewrap` and `proot`, plus macOS `alcless` fallback awareness.
- Added macOS `sandbox-exec` as the default stopgap backend, with session-derived writable path constraints.
- Added a basic policy-aware HTTP proxy and network rule support.
- Added session capability resolution for explicit project mounts, proxied skills, ops execution, and browser automation.
- Added minimal mediated adapters for skills, ops, and browser capability handling.
- Replaced the hardcoded ops bridge with generic config-driven delegates (`run_as_user`, `executor`, `allowed_tools`) and added `agent-jail-cap delegate`.
- Replaced repo-specific mediated-tool names in the broker, docs, and tests with delegate-derived policy and generic public examples.
- Blocked direct execution of sensitive ops and browser tools in favor of `agent-jail-cap`.
- Tightened read-only classification for common inspection commands like `sed -n`, `head`, `sort`, and `printenv`.
- Added delegate support for tool-specific executors via `strip_tool_name`, plus jailed compatibility shims for `python`, `~/build`, and `~/workspace`.
- Added macOS controlling-terminal path discovery so interactive TUIs can access their active TTY device under `sandbox-exec`.
- Added unit and integration tests covering CLI flow, policy matching, backend selection, proxy policy, and wrapper execution.
