# Default Run Profile

`agent-jail` can carry a personal default run profile in `~/.agent-jail/config.json`.

This is useful when you want a plain `agent-jail run ...` invocation to behave like a convenience wrapper without relying on shell aliases.

## Supported Defaults

The `defaults.run` section supports:

- `read_only_roots`
- `write_roots`
- `home_mounts`
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
  --allow-ops \
  --allow-delegate local-secrets \
  --project-mode cwd
```
