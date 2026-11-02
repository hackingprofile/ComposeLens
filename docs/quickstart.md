# Quickstart

This is what ComposeLens (product version `0.1.0`) does. `inspect` is source-level (including canonical dual-form fields). `explain` composes existing stage provenance for one target. `explain --all` emits the whole-model provenance graph. `diff` compares two selections over the same files. `check` runs a fixed ruleset over that model, optionally overlaid by `--policy`. `report --json` / `--html` emit the data package and the offline CSP-hardened viewer packaged in the binary. Redaction defaults apply on every inspect/check/explain/diff/differential/report surface; optional `--redact` overlays extra patterns and specific allowlists (`docs/redact.md`).

## Prerequisites

- Go 1.27.3 or a newer patch release on your PATH (`go.mod` names 1.27.3)
- This source tree (a clone or copy)
- Optional for the **CLI**: Docker CLI with the Compose plugin, only if you want `doctor` to report an engine version or to run `differential`. Detection is optional; the rest of the CLI works without Docker. `differential` runs `docker compose config` and does **not** require the daemon (`docs/privacy.md`).
- Optional for **`go test ./...`**: Docker CLI with the Compose plugin (client-side `docker compose config`; no daemon needed). Live tests compare ComposeLens to `docker compose config`; without a Docker CLI on PATH they **skip** with a message, and the rest of the suite runs. Set `COMPOSELENS_REQUIRE_DOCKER=1` to make a missing Docker CLI fail them instead (the Windows CI job does). That is not a claim that the CLI needs Docker.

## Build and test (local)

From the repository root. If modules are already in your module cache, `GOPROXY=off` is enough (no network). A first checkout may need `go mod download` once.

```bash
go test ./...
go build -o composelens.exe ./cmd/composelens
```

Unix: `go build -o composelens ./cmd/composelens`.

Lint (if golangci-lint v2 is already on PATH; CI pins v2.15.0; ComposeLens does not install it for you):

```bash
golangci-lint run ./...
```

No ComposeLens network service is used.

## 60-second demo (from the repository root)

Stay at the repository root. Pass `--project-directory` so you do not have to `cd` or guess `../` vs `../../`.

Windows:

```bash
.\composelens.exe version --json
.\composelens.exe doctor --json --project-directory examples/precedence-lab
.\composelens.exe inspect --json --project-directory examples/precedence-lab
.\composelens.exe inspect --env-file examples/precedence-lab/extra.env --json --project-directory examples/precedence-lab
.\composelens.exe explain web --json --project-directory examples/precedence-lab
.\composelens.exe check --json --project-directory examples/precedence-lab
.\composelens.exe report --json --project-directory examples/precedence-lab
```

Unix: `./composelens` with the same flags.

Alternatively, after `go build` at the repository root, `cd examples/precedence-lab` and run `../../composelens.exe` (Windows) or `../../composelens` (Unix). Do not use `../composelens`.

### Same commands from a clean directory

Copy only the lab files into an empty folder, then point the already-built binary at that folder. You do not need the rest of the repo at runtime:

```bash
# illustrative layout — use a real empty directory on your machine
composelens doctor --json --project-directory /path/to/copied-precedence-lab
composelens inspect --json --project-directory /path/to/copied-precedence-lab
```

`inspect` is labeled **source-level view — not resolved provenance**. `.env` and `--env-file` values are collected and tagged on the source-level environment view; they are **not** automatically injected into containers. Interpolation uses `--env-file` / `COMPOSE_ENV_FILES` as a **replacement** for the project `.env` (`docs/interpolation.md`). Compose files are merged after interpolation (`docs/merge.md`), include expansion (`docs/include.md`), and extends (`docs/extends.md`). Service profiles are applied after merge (`docs/profiles.md`). Container environment from `environment:` / `env_file:` is a later, separate stage (`docs/containerenv.md`). Canonical dual-form fields appear under `normalization` (`docs/normalize.md`). `explain` composes those stages for one target (`docs/explain.md`). `explain --all` is the whole-model graph (`docs/graph.md`). `diff` compares two profile / env-file selections over the same files (`docs/diff.md`). `check` runs a fixed ruleset (`docs/check.md`). Optional `--policy` is a schema-validated overlay (`docs/policy.md`). `differential` compares the internal model to live `docker compose config` (`docs/differential.md`). `reproduce` prints the exact `docker compose … config` command that recreates the modeled selection (`docs/reproduction.md`); labs live in `examples/reproduce-lab`. Fixture files are indexed in `fixtures/catalog.yaml` (`docs/fixtures.md`); the interpolation/precedence baseline corpus is live-pinned (`docs/corpus.md`). `go test ./internal/fixtax` runs the local harness and corpus runner. Engine `config` capture is documented in `docs/engineadapter.md`. Capability detection is in `docs/enginecap.md`. Overlay, profile, include, extends, container-env, explain, diff, check, graph, and normalization demos live in `examples/merge-lab`, `examples/profiles-lab`, `examples/include-lab`, `examples/extends-lab`, `examples/containerenv-lab`, `examples/explain-lab`, `examples/diff-lab`, `examples/check-lab`, `examples/graph-lab`, and `examples/normalize-lab`. Adoption trees: `docs/examples.md`. Support bundle: `docs/support.md`.

## Common flags

See `docs/cli.md`. Global flags: `--project-directory`, repeated `--file`/`-f`, repeated `--env-file`, `--json`, `--sarif` (`check` only), `--github` (`check` only), `--html` (`report` only), `--bundle` (`doctor` only), `--all` (`explain` only). Composite Action interface: `docs/github-action.md`. Adoption examples: `docs/examples.md`. Support: `docs/support.md`.

## Secrets

Do not pass production secrets to get started. The precedence lab uses non-secret demo values. Adversarial redaction tests generate secrets at runtime and never snapshot them.
