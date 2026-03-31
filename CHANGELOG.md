# Changelog

## Unreleased

- Added the initial `agent-jail` CLI launcher.
- Added command interception through generated PATH wrappers and a local broker.
- Added command normalization, risk classification, allow/deny decisions, and rule learning.
- Added backend selection for Linux `bubblewrap` and `proot`, plus macOS `alcless` fallback awareness.
- Added a basic policy-aware HTTP proxy and network rule support.
- Added session capability resolution for explicit project mounts, proxied skills, ops execution, and browser automation.
- Added minimal mediated adapters for skills, ops, and browser capability handling.
- Blocked direct execution of sensitive ops and browser tools in favor of `agent-jail-cap`.
- Added unit and integration tests covering CLI flow, policy matching, backend selection, proxy policy, and wrapper execution.
