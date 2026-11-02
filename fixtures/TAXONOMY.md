# Fixture kinds

Indexed in `catalog.yaml`. Files stay in their existing directories.

| Kind | Meaning |
| --- | --- |
| `baseline` | Documented / typical Compose behavior |
| `regression` | Issue-derived or repair-locked behavior |
| `platform` | GOOS-specific path cases (`windows` / `posix`) and the Windows compose corpus (bind paths, CRLF/LF, UTF-8 BOM, shell vs exec) |
| `adversarial` | Cycles, unsupported forms, unknown extras, shell-vs-exec, parser-hostile YAML |
| `security` | Secret-safety and active-content corpus (demo values only in catalog files; live secret probes are in-process). `report-xss` rows exercise HTML escaping and JavaScript URLs rendered as text |

Coverage is enumerable by `feature` and `kind` from the harness report (`byFeature`, `byKind`). Interpolation/precedence baseline corpus rows are live-pinned (`docs/corpus.md`). Engine-anchored **regression** rows (`fixtures/regression/`) are live-pinned with a verifiable compose-spec or official-docs rationale. Engine-anchored **platform** compose projects (`fixtures/platform/`) are live-pinned the same way. **Security** rows (`fixtures/security/`) require a verifiable docs/CWE rationale; live tokens are not stored. Other engine results remain `pending-engine`.
