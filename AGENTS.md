# AGENTS

These instructions define the baseline expectations for Codex agents working in this repo.

## Standards

1. Produce production-ready code.
2. Write tests for every change.
3. Run the relevant tests for every change.
4. Document non-obvious logic inline.
5. For larger features, add documentation in `docs/` as markdown.
6. Maintain `CHANGELOG.md` with each improvement.
7. Use the standard commit message format described below.
8. For user interfaces, add user-facing documentation describing each feature.
9. The dev-docs MCP tool must be used to look up relevant API/documentation; use list_metadata to review available datasets, search to locate material, and get_chunk to retrieve the exact passages.

## Commit Message Format

Use `<type>(<scope>): <summary>` where:

- `type` is one of: feat, fix, docs, test, chore, refactor, perf, ci
- `scope` is optional and should be a short noun
- `summary` is a short, imperative description
