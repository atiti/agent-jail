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
- Added config-driven filesystem policy loading for `read_only_roots`, `write_roots`, and `deny_read_patterns`, and render deny-read patterns into the macOS sandbox profile.
- Made delegate execution stream stdout/stderr through `agent-jail-cap delegate ...` and preserve the delegated command's exit code.
- Added shell-chain policy analysis for `bash -c`/`sh -c` command strings, including chained segments, subshells, and command substitutions, while preserving original execution.
- Added contextual low-risk cleanup classification for repo-local generated artifacts such as `__pycache__` directories.
- Added structured JSONL event logging plus `agent-jail monitor`, and moved broker decision logging off interactive stderr by default.
- Added `agent-jail suggest-rules` with Azure OpenAI-backed proposal support, deterministic low-risk validation, and auto-promotion thresholds.
- Added a narrow JIT rule engine for unknown low-risk general commands, with Azure-backed confidence checks, session caching, and review-required fallback on uncertainty.
- Added pending JIT review storage plus `agent-jail review list|approve|reject` so uncertain commands can be operator-approved after the first denial.
- Added interpreter payload analysis for Python, shell, Ruby, and Perl so JIT reviews and approved rules target semantic script behavior instead of launcher noise like `sandbox-exec *`.
- Added broker-side read-scope enforcement for explicit file reads so low-risk tools and interpreted scripts can still be denied when they target paths outside configured readable roots.
- Added a manual shell-based policy validation suite for non-destructive edge cases such as repo reads, system-file reads, relative escapes, `/dev/fd/*`, and conditional `/proc` probes.
- Extended the manual validation suite with standardized stub-JIT cases for auto-allow, pending-review, and reject behavior.
- Added a separate live Azure JIT smoke mode to the manual validation suite for real model behavior checks with semantic rule/review assertions.
- Tightened read-only classification for common inspection commands like `sed -n`, `head`, `sort`, and `printenv`.
- Added delegate support for tool-specific executors via `strip_tool_name`, plus jailed compatibility shims for `python`, `~/build`, and `~/workspace`.
- Added macOS controlling-terminal path discovery so interactive TUIs can access their active TTY device under `sandbox-exec`.
- Added unit and integration tests covering CLI flow, policy matching, backend selection, proxy policy, and wrapper execution.
