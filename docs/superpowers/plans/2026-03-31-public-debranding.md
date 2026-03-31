# Public Debranding Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Remove organization- and user-specific public references from `agent-jail` while keeping the same local functionality through config-driven delegate policy.

**Architecture:** Replace hardcoded mediated tool names and delegate executor paths with config-derived broker behavior, then scrub docs and tests to use generic examples. Keep runtime semantics unchanged for local users who already define delegates in `~/.agent-jail/config.json`.

**Tech Stack:** Python 3 standard library, `unittest`, Markdown docs

---

### Task 1: Make mediated-tool blocking delegate-driven

**Files:**
- Modify: `agent_jail/broker.py`
- Modify: `tests/test_classifier.py`
- Modify: `tests/test_integration.py`

- [ ] **Step 1: Add failing tests for delegate-derived tool blocking**
- [ ] **Step 2: Update the broker to derive mediated tools and executor paths from delegate config**
- [ ] **Step 3: Preserve generic browser and privilege blocking**
- [ ] **Step 4: Run targeted broker and integration tests**
- [ ] **Step 5: Commit**

### Task 2: Replace public examples and docs with generic names

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/specs/2026-03-31-agent-jail-design.md`
- Modify: `docs/superpowers/specs/2026-03-31-agent-jail-lifestyle-design.md`

- [ ] **Step 1: Replace local product and user names with generic examples**
- [ ] **Step 2: Keep examples realistic but not organization-specific**
- [ ] **Step 3: Re-run a repo-wide search for public-specific names**
- [ ] **Step 4: Commit**

### Task 3: Make tests generic and aligned with the new broker behavior

**Files:**
- Modify: `tests/test_capability_cli.py`
- Modify: `tests/test_capability_proxies.py`
- Modify: `tests/test_integration.py`
- Modify: `tests/test_classifier.py`

- [ ] **Step 1: Replace local command names with generic delegated tool examples**
- [ ] **Step 2: Ensure tests explicitly pass delegate config where needed**
- [ ] **Step 3: Run the affected test files**
- [ ] **Step 4: Commit**

### Task 4: Update changelog and verify the public scrub

**Files:**
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a changelog entry for config-driven mediated-tool blocking and public debranding**
- [ ] **Step 2: Run the relevant test suite**
- [ ] **Step 3: Re-run repo-wide grep to confirm the targeted names are gone from tracked files**
- [ ] **Step 4: Commit**
