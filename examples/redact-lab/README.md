# Redaction overlay lab

Tiny Compose project for `--redact` / `composelens.redact.yaml`.

- `add-pattern.yaml` — treat `X_INTERNAL_ID` and `clx_…` values as secret.
- `allowlist.yaml` — same, plus show `PUBLIC_TOKEN` / a documented public placeholder.
- `display-redacted.yaml` — withheld placeholder instead of HMAC fingerprints.
- `invalid-unknown.yaml` — unknown field (must fail typed).

Do not copy live tokens into this folder. Values here are placeholders.
