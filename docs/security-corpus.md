# Privacy / security corpus

This corpus tests secret redaction and active-content escaping across ComposeLens output surfaces.

## What is covered

| Surface | Formats |
| --- | --- |
| `inspect` | human, JSON |
| `explain` / `explain --all` | human, JSON |
| `diff` | human, JSON |
| `check` | human, JSON, SARIF 2.1.0, GitHub workflow annotations (`--github`) |
| `differential` | human, JSON (secret display `[redacted]`; verdict is fingerprint or uncertainty) |
| `report` | JSON, HTML (escaped data island, no live HTML sinks or remote references) |

`TestReportFixtureSafety` renders the three projects under `fixtures/security/report-xss/` through `report --html --no-engine`. Script tags and event handlers must remain escaped JSON data, and JavaScript URLs must stay text. The test rejects live HTML sinks and remote references and verifies each payload is present in the data island. The catalog checks file presence separately; engine comparisons for these rows remain `pending-engine`. `internal/report/hostile_test.go` also tests active content across individual report fields (`docs/report.md`).

## Secret-shaped battery

Fields: `environment` (map and list), `labels`, `command` / `entrypoint` args, `image`, `volumes`, `build.args`.

Shapes: `ghp_` / `gho_` tokens, AWS access-key IDs (`AKIA…`) plus secret keys, URL `user:pass@host`, key-based `PASSWORD` / `TOKEN` / `SECRET` / `API_KEY`, high-entropy tokens, and a secret embedded in a path.

Catalog files under `fixtures/security/secret/` hold **demo placeholders only**. The harness refuses fixture bytes that hold credential material (`internal/redact.ContainsSecretMaterial`). Live probes run in-process in `TestSecurityCorpusSecretBattery`. Its result tables record `redacted=yes` without writing the probe.

## Active-content battery

HTML/`<script>`, ANSI/control characters, JSON/YAML metacharacters, `${…}` / `$(…)` after Compose `$$` escape, CRLF/newline, format-string `%s%n`, and very long values. JSON must unmarshal; SARIF must pass `check.ValidateSARIF`; human/text must not retain ESC/CR/NUL (the output guard replaces leftover C0/DEL bytes with `?`).

## Rationales

Every `kind: security` catalog row has `rationale.type` `docs` or `compose-spec` and an `https://` `ref` (CWE or official GitHub/AWS docs). Docker Compose GitHub issue URLs are not cited.

## Tests

```
go test ./internal/fixtax -run TestSecurityCorpus
go test ./internal/fixtax -run TestReportFixtureSafety
go test ./internal/report -run TestHostile
```

Set `COMPOSELENS_SECURITY_EVIDENCE_DIR` to write `secret-battery-table.txt`, `inert-battery-table.txt`, and `html-fixtures.txt`.
