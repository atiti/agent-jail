# Contributing

Thanks for contributing to `agent-jail`.

## Development workflow

1. Make focused changes.
2. Add or update tests.
3. Update `CHANGELOG.md` when behavior changes.
4. Update docs for operator-facing or user-facing changes.
5. Use the commit format:

```text
<type>(<scope>): <summary>
```

Examples:

```text
fix(policy): deny symlink read escapes
test(suite): add live azure matrix case
docs(readme): clarify delegate model
```

## Verification

Run the full unit suite:

```bash
python3 -m unittest discover -s tests -v
```

Run relevant manual policy suites when changing broker, JIT, or read-scope behavior:

```bash
bash scripts/manual_policy_suite.sh --mode deterministic
bash scripts/manual_policy_suite.sh --mode jit
```

If you are validating the real Azure-backed path:

```bash
bash scripts/manual_policy_suite.sh --mode live-azure-all
```

## Reporting changes

Pull requests should explain:

- the problem
- the design choice
- how it was verified

## Security

Do not commit:

- credentials
- private inventory or host data
- machine-specific secrets

See [SECURITY.md](/Users/attilasukosd/build/agent-jail/SECURITY.md).
