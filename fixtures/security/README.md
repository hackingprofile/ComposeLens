# Privacy / security corpus

Catalog rows under this directory are **structure + rationale** only.

- Secret-shaped probes (`ghp_` / `gho_`, AWS keys, URL userinfo, high-entropy tokens) are **not** stored here. `internal/fixtax.scanSecrets` refuses secret-shaped fixture bytes. Live probes run in-process in `internal/fixtax/security_corpus_test.go`.
- Active-content rows may contain HTML/control-looking text; they are Compose data, not executed.
- `report-xss` rows exercise script-tag escaping, event-handler escaping and JavaScript URLs rendered as text. `TestReportFixtureSafety` renders each fixture through `report --html --no-engine`, checks that the payload survives as JSON data, and rejects live HTML sinks or remote references. Their catalog engine comparisons remain `pending-engine`.
