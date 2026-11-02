Golden files lock **stable CLI bytes** (after path/`numCPU`/HMAC-token stabilization). They must not contain secret values.

- `version.json`, `doctor.json`, `inspect.json`, `explain.json`, `diff.json`, `check.json`, `check.human.txt`, `check.sarif.json`, `check.github.txt` — compared by `TestGoldenStableCLIOutputs`.
- `inspect-schema.keys.txt` — inspect JSON key inventory.
- Report `--json` is locked by SHA-256 `229b526c…` (`TestGoldenReportAnchors`). `internal/report/package.go` stays `5a55a171…`.
- Report `--html` SHA-256 `a4cc8d58…` is the dashboard rebaseline (was `b0912cf4…`). HTML structure/CSS/controller only; data package unchanged.
