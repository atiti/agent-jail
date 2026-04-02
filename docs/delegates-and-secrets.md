# Delegates And Secrets

`agent-jail` keeps secret material outside the sandbox by design. If a command needs host-side credentials, keys, or config files, run it through a configured delegate instead of widening sandbox reads.

## Pattern

1. Keep the session sandboxed.
2. Route the sensitive command through `agent-jail-cap delegate <name> ...`.
3. Define secret capabilities in local config instead of broad secret-path mounts.
4. Let the delegate execute outside the sandbox with host `HOME`/`PATH`.
5. Inject only the configured secret env that the delegated command actually references.

## Example

```json
{
  "secrets": {
    "age_key_file": {
      "env": {
        "AGE_KEY_FILE": "~/.config/agent-jail-demo/age-keys.txt"
      }
    }
  },
  "delegates": [
    {
      "name": "ops",
      "mode": "execute",
      "allowed_tools": ["opsctl"],
      "inventory_tools": ["opsctl"],
      "auto_inventory_from_cwd": true
    },
    {
      "name": "local-secrets",
      "mode": "execute",
      "allowed_tools": ["python3", "./scripts/service-health.sh"],
      "allowed_secrets": ["age_key_file"]
    }
  ]
}
```

With that config:

- `python3 -c "import os; print(os.environ['AGE_KEY_FILE'])"` is denied in the sandbox with a hint to rerun through `agent-jail-cap delegate local-secrets ...`
- `agent-jail-cap delegate local-secrets python3 -c "import os; print(os.environ['AGE_KEY_FILE'])"` receives `AGE_KEY_FILE` from the configured `age_key_file` secret capability
- unrelated configured secrets are not injected unless the delegated command references their env vars

These commands stay mediated even though they rely on host-side secrets:

```bash
agent-jail-cap delegate ops opsctl status --service edge-gateway
agent-jail-cap delegate local-secrets python3 -c "import os; print(os.environ['AGE_KEY_FILE'])"
agent-jail-cap delegate local-secrets ./scripts/service-health.sh summary
```

## Notes

- `secrets` and any secret-bearing env mappings are local configuration and should not be committed to a public repo.
- `allowed_secrets` scopes which secret capabilities a delegate may receive.
- Delegates restore the host user's `HOME` and original `PATH` automatically.
- If `auto_inventory_from_cwd` is enabled and the current working directory contains `inventory/`, delegated inventory-aware tools inherit `--ops-root <cwd> --inventory-dir <cwd>/inventory`.
- The secret files remain unreadable from inside the sandboxed session itself.
