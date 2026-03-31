# Filesystem Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add config-driven filesystem policy so sessions can merge local writable roots, expose configured read-only roots, and deny secret-like reads through sandbox policy.

**Architecture:** Extend config loading with a normalized `filesystem` section, merge configured writable roots into session capability resolution, and render configured deny-read patterns into the macOS sandbox profile. Keep the first slice deterministic and small: no new monitor or LLM behavior yet.

**Tech Stack:** Python 3 standard library, `unittest`, Markdown docs

---

### Task 1: Normalize filesystem config

**Files:**
- Modify: `agent_jail/config.py`
- Test: `tests/test_config.py`

- [ ] **Step 1: Write failing tests for filesystem config normalization**
- [ ] **Step 2: Add normalized `filesystem.read_only_roots`, `filesystem.write_roots`, and `filesystem.deny_read_patterns` loading**
- [ ] **Step 3: Run `python3 -m unittest tests.test_config -v`**
- [ ] **Step 4: Commit**

### Task 2: Merge configured writable and read-only roots into session state

**Files:**
- Modify: `agent_jail/capabilities.py`
- Modify: `agent_jail/main.py`
- Test: `tests/test_capabilities.py`

- [ ] **Step 1: Write failing tests for merged writable and read-only roots**
- [ ] **Step 2: Extend session capability resolution to merge configured roots with explicit args**
- [ ] **Step 3: Keep project roots writable only when explicitly allowed or configured**
- [ ] **Step 4: Run `python3 -m unittest tests.test_capabilities -v`**
- [ ] **Step 5: Commit**

### Task 3: Render deny-read patterns in the macOS sandbox profile

**Files:**
- Modify: `agent_jail/backend.py`
- Test: `tests/test_backend.py`

- [ ] **Step 1: Write failing tests for deny-read pattern rendering**
- [ ] **Step 2: Translate configured deny patterns into sandbox `deny file-read*` rules**
- [ ] **Step 3: Preserve existing writable-path and tty behavior**
- [ ] **Step 4: Run `python3 -m unittest tests.test_backend -v`**
- [ ] **Step 5: Commit**

### Task 4: Document the new filesystem policy

**Files:**
- Modify: `README.md`
- Modify: `CHANGELOG.md`

- [ ] **Step 1: Add a generic example filesystem config to the README**
- [ ] **Step 2: Update changelog**
- [ ] **Step 3: Run the focused suite and a full suite pass**
- [ ] **Step 4: Commit**
