# Manual Policy Suite

Use [manual_policy_suite.sh](/Users/attilasukosd/build/agent-jail/scripts/manual_policy_suite.sh) to hand-run a non-destructive edge-case validation pass against `agent-jail`.

What it does:

- creates an isolated temporary `AGENT_JAIL_HOME` by default
- writes a deterministic config with:
  - `~/build` readable
  - `~/workspace` writable
  - JIT disabled for stable outcomes
- runs a set of allow/deny edge cases
- prints colorized `PASS`, `FAIL`, or `OBSERVE` for each case
- groups cases by area such as read scope, interpreters, devices, and procfs
- keeps the suite extensible through a simple case registry in the script
- supports both deterministic policy cases and standardized JIT cases

List the cases without running them:

```bash
bash scripts/manual_policy_suite.sh --list
```

Run the suite:

```bash
bash scripts/manual_policy_suite.sh
```

Run only deterministic or JIT cases:

```bash
bash scripts/manual_policy_suite.sh --mode deterministic
bash scripts/manual_policy_suite.sh --mode jit
bash scripts/manual_policy_suite.sh --mode live-azure
bash scripts/manual_policy_suite.sh --mode live-azure-all
```

Keep the temporary state directory for inspection:

```bash
bash scripts/manual_policy_suite.sh --keep-state
```

Use an explicit home directory:

```bash
bash scripts/manual_policy_suite.sh --home /tmp/agent-jail-manual
```

Covered cases include:

- repo-local reads that should pass
- direct system file reads that should fail
- relative escapes outside the repo
- normalized and obfuscated path reads such as `/etc/../etc/passwd`
- shell pipelines over forbidden paths
- Python literal, variable-based, and `pathlib` reads of forbidden paths
- Ruby and Perl direct reads of forbidden paths
- `/dev/fd/*` path reads
- `/proc` reads when available on the host
- shell indirection tricks such as variable expansion, command substitution, and `xargs`-mediated reads
- an `OBSERVE` case for `dmesg`, which is intentionally reported as current behavior rather than locked to a pass/fail expectation
- stubbed JIT auto-allow, review, and reject cases with assertions on `policy.json`
- a live Azure JIT smoke case that asserts sane semantic behavior for a low-risk interpreted command
- a live Azure matrix mode that runs several JIT-eligible commands against the real model

To extend the suite, add another `add_case` entry in [manual_policy_suite.sh](/Users/attilasukosd/build/agent-jail/scripts/manual_policy_suite.sh). Each case declares:

- name
- expectation (`allow`, `deny`, `deny-or-missing`, or `observe`)
- group
- description
- command argv

For JIT cases, add `add_jit_case` entries instead. Those cases run against isolated stubbed JIT profiles and verify side effects such as:

- rule insertion
- semantic template matching
- pending review creation
- deduped review IDs on rerun

`--mode live-azure` and `--mode live-azure-all` are intentionally separate from the stubbed mode. They require:

- `AZURE_OPENAI_ENDPOINT`
- `AZURE_OPENAI_API_KEY`
- `AZURE_OPENAI_DEPLOYMENT`

Live Azure modes accept either:

- auto-allow with a persisted semantic rule
- or a semantic pending review

They are smoke tests for real model behavior, not deterministic regression gates.

In the live Azure profiles, low-risk read-only commands are intentionally forced through the JIT path so the real model is exercised on commands like `tree` and read-only shell pipelines instead of those commands being short-circuited by the deterministic broker allow path.

`--mode live-azure` runs the single baseline smoke case.

`--mode live-azure-all` runs the current live matrix of JIT-eligible commands, including:

- direct `tree` inspection
- a read-only shell pipeline
- a low-risk Python subprocess inspection script

Each case in the manual suite now runs in its own isolated `AGENT_JAIL_HOME`, so approvals, reviews, and learned rules do not leak between cases.

These outcomes are explicit failures in `--mode live-azure`:

- `jit request failed: timeout`
- `jit http error: ...`
- `jit provider unavailable: ...`
- malformed JIT response payload errors

The suite is meant to prove current policy boundaries without mutating your real `~/.agent-jail/policy.json`.
