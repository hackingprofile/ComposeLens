# Compatibility

## ComposeLens

Product version (see `composelens version --json`): **0.1.0**. This documentation describes product version **0.1.0**.

| Item | Value |
| --- | --- |
| Language | Go 1.27.3 (the `go` line in `go.mod`; CI installs exactly this release) |
| Lint | golangci-lint v2.15.0 with `.golangci.yml` (version 2 format), as pinned in `ci.yml` |
| Module | `composelens` |
| CLI | `doctor`, `inspect`, `explain` (including `--all`), `diff`, `check` (human / `--json` / `--sarif` / `--github`), `differential`, `reproduce`, `report --json`, `report --html`, `version`. Human `report` (no `--json` / `--html`) is typed `unsupported` (exit 5). |

## Recognized Compose family vs recorded engine values

Two different claims. Do not collapse them.

| Claim | Meaning | Status |
| --- | --- | --- |
| **Recognized family** | The parser and capability map treat Docker Compose **plugin major ≥ 2** (Compose Specification / `docker compose`, not Compose v1 `1.x`) as in-window. Doctor JSON emits `engineCapabilities.support: "recognized"` with detail that this is family recognition, not a tested matrix. | Code behavior (`internal/enginecap`). Compose **v1** is typed `unsupported`. Unparseable versions are `unknown`. |
| **Recorded engine values** | The live corpus (`docs/corpus.md`) holds engine values recorded with Docker Compose plugin **v5.4.0** and Docker Engine **29.7.2**. Live tests compare against whatever Compose release is installed and log that release next to the recorded one. | Engine-version-dependent output (the engine version string, an implied `create_host_path` on short bind mounts) is normalized, so other releases compare row by row. |
| **Full matrix** | Every other Compose 2.x / 5.x and engine combination. | **Not claimed.** |

ComposeLens **parses Compose YAML/JSON as files**, resolves Compose interpolation expressions locally (see `docs/interpolation.md`), expands top-level `include:` (see `docs/include.md`), resolves service `extends` (see `docs/extends.md`), merges interpolated files in order (see `docs/merge.md`), applies service profiles on the merged model (see `docs/profiles.md`), resolves the container environment from `environment:` / `env_file:` (see `docs/containerenv.md`), and canonicalizes documented dual-form fields (see `docs/normalize.md`). `explain` composes those stage results for one target (see `docs/explain.md`). `explain --all` assembles those accounts into a whole-model graph (see `docs/graph.md`). `diff` compares two profile / env-file selections over the same files (see `docs/diff.md`). `check` runs a fixed ruleset over that effective model (see `docs/check.md`). Optional `check --policy` loads a schema-validated overlay (see `docs/policy.md`). `report --json` / `--html` assemble that model (`docs/report.md`). Fixtures are indexed in place with declared expectations (see `docs/fixtures.md`). Interpolation and container-env corpus rows carry recorded engine values (see `docs/corpus.md`); the privacy/security corpus is documented in `docs/security-corpus.md`; other engine results stay `pending-engine`. An engine adapter can capture redacted `docker compose config` when Docker is already present (see `docs/engineadapter.md`). `composelens differential` compares the internal model to that capture (see `docs/differential.md`); that is not a claim of full engine parity. Representation gaps D1 (bind source as written), D2 (shell vs exec), D3 (engine implicit default network) and D4 (default text nested deeper than 8 levels) are classified; unrelated disagreements stay bare. `composelens reproduce` prints the file/flag `docker compose … config` command that recreates that selection (see `docs/reproduction.md`). Long-form include `env_file` and `project_directory` are not applied. String short-form `extends` is unsupported. Dockerfile `ENV` is not read.

Intended input window (parse, **not** a verified-engine matrix):

- Compose file format 3.x and Compose Specification YAML commonly used with the Docker Compose v2+ plugin family
- JSON Compose files (parsed via YAML, which accepts JSON)
- Files with several YAML documents, merged in order as Compose merges them

Unsupported (typed `unsupported` / deferred — not guessed):

- String short-form `extends` (Compose Specification requires a mapping)
- Applying include `env_file` / `project_directory`
- Dockerfile `ENV` / image environment (no image is read)
- `docker compose run -e` runtime CLI
- Default text nested deeper than 8 levels (kept as written, certainty `unknown`)
- Full `docker compose config` parity (the differential reports divergences instead of claiming agreement; sequence overlay rules are live-checked in `docs/merge.md`)

Input Compose rejects (an unknown top-level key, an invalid interpolation format, an `include:` that is not a list, include or extends cycles) is reported by `check` as `CHK06` and never shown as `proven` (`docs/check.md`).

## Host platforms

Source is cross-platform (`filepath`, explicit `GOOS` fixtures). `.github/workflows/ci.yml` builds, tests and lints on every platform below; the Linux leg also runs `go test -race`.

| Platform | CI leg | Live engine tests |
| --- | --- | --- |
| Linux | `ubuntu-latest` | Run (Docker CLI present; required with `COMPOSELENS_REQUIRE_DOCKER=1`) |
| macOS | `macos-latest` | Skip with a stated reason (no Docker CLI on the runner) |
| Windows | `windows-latest` | Run (Docker CLI present; required with `COMPOSELENS_REQUIRE_DOCKER=1`) |

Path-resolution fixtures exist for Windows and POSIX. Tests run the fixture matching `runtime.GOOS` and skip the other, recording that skip. Platform-specific behaviour (special files such as FIFOs and `/proc`, symlinks) is covered by build-tagged tests that run on the platform they describe.

## Shells

`doctor` reports a detected shell when possible (`powershell`, `pwsh`, `cmd`, or `$SHELL`). Detection is best-effort: `SHELL` on Linux and macOS is `proven`; Windows detection is `inferred`.

## Engine detection

If the Docker CLI is missing, `doctor` reports engine state `absent`. That is success for doctor, not a product failure. A detected Compose **plugin major ≥ 2** is the **recognized** family (`docs/enginecap.md`); Compose v1 is typed `unsupported`. Corpus engine values were recorded with Docker Compose **v5.4.0** / Engine **29.7.2**. `composelens differential` reports divergences vs live `docker compose config` (`docs/differential.md`); it does not claim render parity. `composelens reproduce` prints the file/flag command that recreates the modeled selection (`docs/reproduction.md`).
