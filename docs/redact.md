# Redaction configuration

ComposeLens redacts secret **keys** and secret-**shaped values** by default (`internal/redact`). An optional, schema-validated overlay lets a site **add** detection and **allowlist** specific false positives without changing the accepted defaults.

## File and flag

- Flag: `--redact <file>` on project-reading commands (`doctor`, `inspect`, `explain`, `diff`, `check`, `differential`, `reproduce`, `report`).
- Discovery: if `--redact` is omitted and the project directory contains `composelens.redact.yaml`, that file is loaded.
- No file and no flag: **defaults unchanged**.
- Invalid, oversized, or over-budget configs fail typed (exit `3`) **before** analysis. The file is charged against the shared invocation budget (`docs/limits.md`).

Schema id: `composelens.redact.v0`. Unknown fields, duplicate keys, YAML anchors/aliases/merge/custom tags, multiple documents, and trailing content are rejected (same discipline as `docs/policy.md`).

```yaml
schema: composelens.redact.v0
# display: fingerprint   # default — per-run HMAC token (inspect)
# display: redacted      # withheld placeholder [redacted]
secretKeys:
  - X_INTERNAL_ID          # extra key names (exact, case-insensitive) or regex
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"  # extra value patterns (regex)
allowKeys:
  - PUBLIC_TOKEN           # exact key names only — not a blanket allow
allowValues:
  - license-spdx-mit       # exact public values only
```

The config declares **patterns and names**, never live secrets. A secret-shaped string in `secretKeys` / `secretValues` is rejected; the diagnostic does not echo it.

Allowlist entries must be **specific**. `.*`, `.+`, `*`, and other match-everything patterns are refused. An allowlisted **key** skips key-name classification; a value that still looks like a secret (default or added pattern) stays redacted. An allowlisted **value** is shown; other secrets in the same project stay redacted.

## Irreversible display tokens

A withheld value is shown as:

- `[redacted]` — the withheld placeholder (`display: redacted`), or
- `hmac-sha256:` plus 16 bytes of HMAC-SHA256 hex — the per-run **fingerprint** (default `display: fingerprint`).

Neither form is the raw value. Neither is reversible encoding (not base64, not a truncated secret). The HMAC key is 32 bytes from `crypto/rand`, generated once per CLI invocation, held for `internal/safety.Guard`, and **never emitted**. Fingerprints match **inside one run** and **differ across runs**. Inspect JSON keeps the `fingerprint` field; with `display: redacted` a secret row’s fingerprint is `[redacted]`.

Human `explain` / `diff` / `check` / `differential` surfaces continue to withhold secrets as `[redacted]`. The overlay changes **what counts as a secret** on every redacting surface, including engine-adapter capture used by `differential`.

## Bar

Raw secrets — including a value matched **only** by a custom pattern — must not appear in human, JSON, or SARIF output, tests’ stored evidence, or diagnostics. The fail-closed guard still scans known secret fragments and fingerprint-key material.

Compose interpolation brace forms (`${VAR:-default}`) and `$$` are stripped before the length/entropy classifier so a benign defaulted image is not treated as a leak. Known secret patterns are still matched on the full string; secret resolved values still redact. Bare `$VAR` is left as written so mixed-alphabet tokens that happen to contain `$` still redact. When a value is already secret-designated, inspect withholds the raw interpolation expression so a non-token default cannot leak.
