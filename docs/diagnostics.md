# Diagnostics

Every failure **kind/code** ComposeLens emits is catalogued in `internal/diag`. Each entry has a stable id, a message template, a remediation hint, and an in-repo documentation path. Templates never contain secrets.

The typed error document `composelens.error.v0` now carries `code`, `remediation`, and `doc` beside `message`. Human stderr prints the same three fields after `composelens: …`. Exit codes and control flow are unchanged.

`check` findings that meet the severity gate (exit 6) include the same `code` / `remediation` / `doc` fields on `composelens.check.v0` (`exit.assertion`). `report --json` copies those catalog entries into `diagnostics` when they are surfaced (`docs/report.md`).

## Families

| Prefix | Source | Docs |
| --- | --- | --- |
| `exit.*` / `cli.usage` | Process exit classes | [CLI](cli.md) |
| `policy.*` | Policy overlay load | [Policy](policy.md) |
| `redact.*` | Redaction config load | [Redact](redact.md) |
| `safety.*` | Parser and input budget | [Parser](parser.md), [Limits](limits.md) |

A completeness test parses the exported `Kind` / `Code` constants and fails if any id is missing from the catalog.

## Exit codes

See [CLI exit codes](cli.md#exit-codes). Catalog ids: `exit.internal`, `cli.usage`, `exit.input`, `exit.safety`, `exit.unsupported`, `exit.assertion`.
