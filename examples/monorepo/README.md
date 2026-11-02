# Monorepo adoption example

Several apps, each with its own Compose file, plus an optional shared overlay.

Placeholder/demo values only (`APP_ENV: demo`, `COLOR: blue`). No real secrets.

Exact invocations and expected exits: `docs/examples.md`.
The local runner is `go test ./internal/adoption` (CI execution is deferred).
