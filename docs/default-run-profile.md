# Default Run Profile

`agent-jail` can carry a personal default run profile in `~/.agent-jail/config.json`.

This is useful when you want a plain `agent-jail run ...` invocation to behave like a convenience wrapper without relying on shell aliases.

## Supported Defaults

The `defaults.run` section supports:

- `read_only_roots`
- `write_roots`
- `home_mounts`
- `git_ssh_hosts`
- `allow_ops`
- `allow_delegates`
- `project_mode`

Current `project_mode` values:

- `cwd`: treat the current working directory as the default project root

## Example

```json
{
  "defaults": {
    "run": {
      "read_only_roots": ["~/build"],
      "write_roots": ["~/workspace"],
      "home_mounts": [".config/opencode", ".overwatchr"],
      "git_ssh_hosts": ["github.com"],
      "allow_ops": true,
      "allow_delegates": ["local-secrets"],
      "project_mode": "cwd"
    }
  }
}
```

With this profile:

- the current working directory is mounted read-write by default
- `~/build` is mounted read-only
- `~/workspace` is mounted read-write
- `~/.config/opencode` and `~/.overwatchr` are mirrored into the jailed home
- Git SSH transport is allowed to `github.com` for normal `git push` / `git fetch` SSH remotes
- ops capability is enabled by default
- `local-secrets` is allowed by default

Explicit CLI flags still win. For example:

- `--no-allow-ops` disables default ops for a single run
- `--project` and `--allow-write` still let you shape a session explicitly

## Managing It

Show the active normalized config:

```bash
python3 agent-jail config show
```

Set the defaults from the CLI:

```bash
python3 agent-jail config set-defaults \
  --read-only-root ~/build \
  --write-root ~/workspace \
  --home-mount .config/opencode \
  --git-ssh-host github.com \
  --allow-ops \
  --allow-delegate local-secrets \
  --project-mode cwd
```

`git_ssh_hosts` only opens the narrow Git SSH transport path to listed hosts. Arbitrary `ssh host ...` commands remain blocked by broker policy.

`home_mounts` are for stateful tool directories under your home folder that should stay live inside the jailed home, such as `.overwatchr`, `.config/opencode`, or another app-specific state directory. They are mirrored into the jailed home as writable symlinks instead of being hardcoded in the launcher.

On macOS, agent startup uses the real host binary path for the top-level tool and then hands a wrapped `PATH` to child processes inside the session. This avoids brittle bootstrap failures with package-manager shims while preserving normal jailed command interception once the agent is running.
