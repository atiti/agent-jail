# Changelog

## Unreleased

- Added the initial `agent-jail` CLI launcher.
- Added command interception through generated PATH wrappers and a local broker.
- Added command normalization, risk classification, allow/deny decisions, and rule learning.
- Added Linux backend selection for `bubblewrap` and `proot`, with host-mode fallback.
- Added a basic policy-aware HTTP proxy and network rule support.
- Added unit and integration tests covering CLI flow, policy matching, backend selection, proxy policy, and wrapper execution.
