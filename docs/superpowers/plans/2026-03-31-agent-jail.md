# Agent Jail Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a small Python 3 CLI that launches an AI agent CLI under a PATH-injected wrapper layer and routes intercepted commands through a broker for normalization, policy, risk, logging, rule learning, backend selection, capability gating, and optional proxy-based network control.

**Architecture:** Use a Python launcher and broker with POSIX shell wrappers generated into a temporary session directory. On Linux, prefer `bubblewrap`, then `proot`, with optional advanced `chroot`; on macOS, prefer `alcless`, offer `lima`, then fall back to host mode with clear limits. Add a capability layer so project mounts, secret-bearing skills, production operations, and browser automation can be mediated separately. Keep policy persistence in a single JSON file under the user home directory, use a tiny explicit proxy for outbound policy checks, and cover the behavior with standard-library `unittest`.

**Tech Stack:** Python 3 standard library, POSIX shell wrappers, `unittest`

---

### Task 1: Scaffold the package and CLI entrypoint

**Files:**
- Create: `agent_jail/__init__.py`
- Create: `agent_jail/main.py`
- Create: `agent-jail`
- Test: `tests/test_cli.py`

- [ ] **Step 1: Write the failing CLI tests**

```python
def test_run_requires_target():
    code, out, err = run_cli([])
    self.assertNotEqual(code, 0)

def test_run_invokes_launcher():
    code, out, err = run_cli(["run", "echo", "hi"])
    self.assertEqual(code, 0)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_cli.py -v`
Expected: fail because package and command do not exist yet

- [ ] **Step 3: Write minimal implementation**

```python
def main(argv=None):
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_cli -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/__init__.py agent_jail/main.py agent-jail tests/test_cli.py
git commit -m "feat(cli): add agent-jail launcher entrypoint"
```

### Task 2: Add normalization and risk classification

**Files:**
- Create: `agent_jail/broker.py`
- Test: `tests/test_classifier.py`

- [ ] **Step 1: Write the failing normalization and classifier tests**

```python
def test_normalize_git_push():
    intent = normalize(["git", "push", "origin", "main"])
    self.assertEqual(intent["tool"], "git")
    self.assertEqual(intent["action"], "push")
    self.assertEqual(intent["target"], "origin/main")

def test_classify_force_push_as_high():
    intent = normalize(["git", "push", "--force"])
    self.assertEqual(classify(intent, ["git", "push", "--force"])["risk"], "high")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_classifier -v`
Expected: FAIL because functions are missing

- [ ] **Step 3: Write minimal implementation**

```python
def normalize(argv):
    ...

def classify(intent, argv):
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_classifier -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/broker.py tests/test_classifier.py
git commit -m "feat(broker): add command normalization and risk classification"
```

### Task 3: Add policy loading, matching, and learning

**Files:**
- Create: `agent_jail/policy.py`
- Test: `tests/test_policy.py`

- [ ] **Step 1: Write the failing policy tests**

```python
def test_matching_rule_allows_safe_push():
    ...

def test_learning_generates_non_force_push_rule():
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_policy -v`
Expected: FAIL because policy helpers are missing

- [ ] **Step 3: Write minimal implementation**

```python
class PolicyStore:
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_policy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/policy.py tests/test_policy.py
git commit -m "feat(policy): add JSON policy matching and rule learning"
```

### Task 4: Add backend selection and proxy decisions

**Files:**
- Create: `agent_jail/backend.py`
- Create: `agent_jail/proxy.py`
- Test: `tests/test_backend.py`
- Test: `tests/test_proxy.py`

- [ ] **Step 1: Write the failing backend and proxy tests**

```python
def test_linux_prefers_bwrap_when_available():
    ...

def test_macos_prefers_alcless_when_available():
    ...

def test_proxy_denies_unknown_host_when_default_is_deny():
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_backend tests.test_proxy -v`
Expected: FAIL because backend and proxy helpers are missing

- [ ] **Step 3: Write minimal implementation**

```python
def choose_backend(...):
    ...

class ProxyPolicy:
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_backend tests.test_proxy -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/backend.py agent_jail/proxy.py tests/test_backend.py tests/test_proxy.py
git commit -m "feat(runtime): add backend selection and proxy policy"
```

### Task 5: Add capability resolution and session resource mapping

**Files:**
- Create: `agent_jail/capabilities.py`
- Modify: `agent_jail/main.py`
- Modify: `agent_jail/policy.py`
- Test: `tests/test_capabilities.py`

- [ ] **Step 1: Write the failing capability tests**

```python
def test_session_projects_expand_to_explicit_mounts():
    ...

def test_secret_bearing_skills_default_to_proxy_mode():
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_capabilities -v`
Expected: FAIL because capability helpers are missing

- [ ] **Step 3: Write minimal implementation**

```python
def resolve_session_capabilities(...):
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_capabilities -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/capabilities.py agent_jail/main.py agent_jail/policy.py tests/test_capabilities.py
git commit -m "feat(capabilities): add session capability resolution"
```

### Task 6: Add wrapper generation and broker server flow

**Files:**
- Create: `agent_jail/wrappers.py`
- Modify: `agent_jail/broker.py`
- Modify: `agent_jail/main.py`
- Test: `tests/test_integration.py`

- [ ] **Step 1: Write the failing integration tests**

```python
def test_wrapper_allows_safe_git_status():
    ...

def test_wrapper_denies_remote_exec_shell():
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_integration -v`
Expected: FAIL because wrappers and socket server are missing

- [ ] **Step 3: Write minimal implementation**

```python
def serve_forever(...):
    ...

def write_wrappers(...):
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_integration -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/wrappers.py agent_jail/broker.py agent_jail/main.py tests/test_integration.py
git commit -m "feat(exec): add broker socket flow and generated command wrappers"
```

### Task 7: Add proxied sensitive capability adapters

**Files:**
- Create: `agent_jail/skills_proxy.py`
- Create: `agent_jail/ops_proxy.py`
- Create: `agent_jail/browser_proxy.py`
- Modify: `agent_jail/broker.py`
- Test: `tests/test_capability_proxies.py`

- [ ] **Step 1: Write the failing proxy capability tests**

```python
def test_ops_exec_requires_capability_allow():
    ...

def test_browser_automation_routes_to_host_proxy():
    ...
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python3 -m unittest tests.test_capability_proxies -v`
Expected: FAIL because capability proxy adapters are missing

- [ ] **Step 3: Write minimal implementation**

```python
def run_ops_proxy(...):
    ...
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python3 -m unittest tests.test_capability_proxies -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add agent_jail/skills_proxy.py agent_jail/ops_proxy.py agent_jail/browser_proxy.py agent_jail/broker.py tests/test_capability_proxies.py
git commit -m "feat(proxy): add mediated skills ops and browser adapters"
```

### Task 8: Finish docs and release ergonomics

**Files:**
- Modify: `README.md`
- Create: `CHANGELOG.md`

- [ ] **Step 1: Write the failing documentation expectation**

Document expected commands and examples in the README and changelog before claiming completion.

- [ ] **Step 2: Update docs**

Add:

- installation and usage
- `agent-jail run codex --yolo`
- `agent-jail run claude`
- backend matrix: `bubblewrap`, `proot`, `alcless`, `lima`, `chroot`
- known limits for absolute-path shell invocation
- project mount strategy
- why secrets, ops, and browser automation should be proxied

- [ ] **Step 3: Run the full test suite**

Run: `python3 -m unittest discover -s tests -v`
Expected: PASS

- [ ] **Step 4: Do a manual smoke test**

Run: `python3 agent-jail run python3 -c "print('ok')"`
Expected: `ok`

- [ ] **Step 5: Commit**

```bash
git add README.md CHANGELOG.md
git commit -m "docs: add usage and release notes for agent-jail"
```
