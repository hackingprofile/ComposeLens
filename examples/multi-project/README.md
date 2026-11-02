# Multiple independent Compose projects

`shop` and `billing` are **separate** projects. Analyze them with two `--project-directory` invocations — do not merge them with multi-`--file`.

Placeholder/demo values only. No real secrets.

Exact invocations and expected exits: `docs/examples.md`.
The local runner is `go test ./internal/adoption` (CI execution is deferred).
