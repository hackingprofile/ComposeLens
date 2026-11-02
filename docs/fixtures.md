# Fixture taxonomy and metadata format

ComposeLens indexes existing test fixtures in place. This is **not** a user-facing CLI command and **not** an engine differential. Every fixture file under `fixtures/` is declared in `fixtures/catalog.yaml` (`schema: composelens.fixtax.v0`). Fixture bytes are not moved or rewritten.

Doctor lists `fixture-taxonomy` as implemented. Engine comparison is `composelens differential` (`docs/differential.md`), not this catalog.

## Catalog fields

Each catalog entry declares:

| Field | Meaning |
| --- | --- |
| `id` | Stable identifier (`feature.case`) |
| `feature` | Category exercised (`yaml`, `paths`, `interpolation`, `merge`, `profiles`, `include`, `extends`, `container-env`, `explain`, `diff`, `check`, `graph`, `normalization`, `secret-safety`, …) |
| `kind` | `baseline` / `regression` / `platform` / `adversarial` / `security` |
| `description` | Short intent |
| `provenance.source` | `official` / `issue-derived` / `adversarial` / `synthetic` |
| `rationale` | Required on engine-anchored `kind: regression` and `kind: platform` rows, and on every `kind: security` row: `type` (`compose-spec` / `docs`), `ref` (https URL), optional `section`. Issue URLs are not fabricated. |
| `files` | Repo-relative paths under `fixtures/` (slash-separated). Content is unchanged. |
| `entry` | Optional compose entry when it is not `files[0]` |
| `expected.engine` | `pending-engine` (not live-pinned), `matched`, `divergent`, or `engine-error`. Guessed engine values are rejected. Anchored rows require `enginePin` (this corpus: `v5.4.0`). |
| `expected.enginePin` | Compose version the row was live-validated against. |
| `expected.engineFields` | In-scope paths and live engine values (from `docker compose config`, not from ComposeLens). |
| `expected.local` | Locally checkable assertion (parse, merge, interp, profiles, include, extends, container-env, check IDs, normalize equality, path cases). |

Kinds are enumerated in `fixtures/TAXONOMY.md`.

## Harness

`internal/fixtax.Run` loads the catalog, fails if any on-disk `.yaml` / `.yml` / `.json` / `.env` file is undeclared (skipping `catalog.yaml`, `TAXONOMY.md`, `README.md`, `meta.yaml`), runs local assertions, and reports coverage by feature and kind.

- **passed** — local assertion held
- **failed** — local assertion did not hold
- **skipped** — platform fixture whose `goos` does not match this process (`posix` means non-Windows)
- **pendingEngine** — counted for rows still marked `pending-engine`

Live-pinned interpolation/precedence baseline rows are enforced by `TestLiveBaselineCorpus` (`docs/corpus.md`). Live-pinned **regression** rows (`kind: regression`) are enforced by `TestLiveRegressionCorpus` and must include a verifiable `rationale`. Live-pinned **platform** rows (`kind: platform`) are enforced by `TestLivePlatformCorpus` (Windows paths, newlines, encoding, shell/command) and also require a verifiable `rationale`. **Security** rows (`kind: security`) require a verifiable `rationale` and are exercised by `TestSecurityCorpus*` (`docs/security-corpus.md`). Other engine results stay `pending-engine`.

JSON shape: `composelens.fixtax.v0`. The harness is invoked from `go test ./internal/fixtax`. There is no `composelens fixtures` command.

Credential material in declared files (a vendor token, embedded URL or connection-string credentials, or a run shaped like a generated key) fails the run via `internal/redact.ContainsSecretMaterial`. Fixtures must not store live tokens.

## Index, do not move

Existing tests continue to load `fixtures/...` paths. Adding a fixture requires a catalog row with a real local assertion. Engine-anchored interpolation/precedence/regression/platform rows use `matched` / `divergent` / `engine-error` plus `enginePin` (`docs/corpus.md`). Regression, platform, and security rows also require a verifiable `rationale`. Other features stay `pending-engine`.
