# Docker Compose engine adapter

ComposeLens can **invoke** a provided Docker Compose CLI to capture authoritative `version` and `config` output. This is **not** a differential, **not** capability detection beyond the version string, and **not** a user-facing CLI command.

Doctor lists `compose-engine-adapter` as implemented. `composelens differential` consumes these captures (`docs/differential.md`). This adapter is still not a user-facing CLI command.

## What it does

`internal/engineadapter` runs, for a project/selection:

1. `docker compose version` (or `docker-compose version`)
2. `docker compose --project-directory … -f … config`

It records the exact command, exit code, timestamp, engine version, and a SHA-256 digest of the **redacted** config stdout.

It never pulls images or starts containers. Stdout and stderr are read through a **bounded buffer** (`safety.MaxEngineOutputBytes`, 4 MiB per stream) and charged against the shared invocation budget (`docs/limits.md`). Over-cap capture is a typed safety diagnostic (exit 3 on `differential`); the truncated stream is not retained.

## Typed results

| State | Meaning |
| --- | --- |
| `captured` | Engine ran `config` with exit 0; stdout is redacted |
| `engine-absent` | Docker CLI not on PATH — **no fabricated config** |
| `engine-error` | CLI present but the command failed |
| `unsupported` | Verb other than `version` / `config` (adapter refuses) |

Live capture requires Docker on PATH. ComposeLens does **not** install Docker. When Docker is absent, unit tests use secret-free recorded samples under `internal/engineadapter/testdata/`.

## Secret safety

Engine `config` output can contain fully resolved secrets. Every retained byte is redacted through `internal/redact` (secret keys and `LooksLikeSecret` values). `internal/safety.Guard` fail-closes if a collected secret would remain. Raw secret-bearing engine output is never written to test evidence or fixtures.

## JSON

Schema `composelens.engineadapter.v0`. Not emitted by `inspect` / `explain` / `diff` / `check`.
