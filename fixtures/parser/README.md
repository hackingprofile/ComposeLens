# Parser hardening fixtures

Hostile or boundary Compose inputs for the bounded parser/loader. Failing cases use catalog `files-exist` (they must not parse). Outcomes are asserted in `go test ./internal/composeparse` and `./internal/discover`. See `docs/parser.md`.
