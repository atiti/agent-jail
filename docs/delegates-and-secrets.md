# Delegates And Secrets

`agent-jail` keeps secret material outside the sandbox by design. If a command needs host-side credentials, keys, or config files, run it through a configured delegate instead of widening sandbox reads.

## Pattern

1. Keep the session sandboxed.
2. Route the sensitive command through `agent-jail-cap delegate <name> ...`.
3. Let the delegate execute outside the sandbox with host `HOME`/`PATH`.
4. Inject only the explicit environment values the delegated tool needs.

## Example

```json
{
  "delegates": [
    {
      "name": "ops",
      "mode": "execute",
      "allowed_tools": ["privateinfractl", "./scripts/unifi-api.sh"],
      "set_env": {
        "AGE_KEY_FILE": "~/.marksterctl/age/keys.txt"
      }
    }
  ]
}
```

With that config, these commands stay mediated even though they rely on host-side secrets:

```bash
agent-jail-cap delegate ops privateinfractl status --service nas-unifi-controller
agent-jail-cap delegate ops ./scripts/unifi-api.sh devices
```

## Notes

- `set_env` is local configuration and should not be committed to a public repo.
- Delegates restore the host user's `HOME` and original `PATH` automatically.
- The secret files remain unreadable from inside the sandboxed session itself.
