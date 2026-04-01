# Read Scope Enforcement

Date: 2026-04-01
Status: Completed

## Goal

Prevent low-risk read tools from reading arbitrary host files outside configured readable roots.

## Change

- add broker-side read-scope checks for explicit file/path operands
- enforce the same boundary for shell payloads and interpreter payloads
- keep root policy deterministic and non-learnable

## Examples

- allow: `cat README.md` inside a mounted repo
- deny: `cat /etc/passwd`
- deny: `python3 -c "print(open('/etc/passwd').read())"`

## Notes

This is intentionally separate from general tool risk. A command can be low risk as a category and still be denied because it targets a path outside the configured readable roots.
