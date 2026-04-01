# Interpreter Payload Analysis Plan

Date: 2026-04-01
Status: In Progress

## Steps

1. Add a script-analysis module that can:
   - unwrap `sandbox-exec`
   - inspect Python payloads and local `.py` files
   - inspect shell command strings and local shell scripts
   - heuristically scan Ruby and Perl payloads
2. Thread semantic templates into broker intent normalization and event templates.
3. Bind JIT-added and review-approved rules to semantic templates through rule constraints.
4. Add regression tests for:
   - launcher unwrapping
   - Python `-c` subprocess inspection
   - shell read-only scripts
   - deduped pending reviews using semantic templates
5. Update public documentation and changelog.
