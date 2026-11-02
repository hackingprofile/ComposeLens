# Baseline corpus

Primary interpolation grammar and container-environment precedence fixtures live under `fixtures/corpus/` and in the existing `fixtures/containerenv/` baselines. Every row is declared in `fixtures/catalog.yaml`.

Expected engine results are **live-pinned** to Docker Compose **v5.4.0** (daemon-backed `docker compose` plugin) via `composelens differential` (`docs/differential.md`). Catalog `expected.engine`:

| Value | Meaning |
| --- | --- |
| `pending-engine` | Not yet live-pinned (other features) |
| `matched` | In-scope interpolation/precedence fields MATCH the pinned engine |
| `divergent` | Honest in-scope disagreement (recorded, not hidden) |
| `engine-error` | Live `docker compose config` fails; that failure is the pin |

`enginePin` is required on anchored rows and records the Compose version that supplied the values. The runner accepts any installed Compose version and compares each field. `engineFields` are copied from engine output. The corpus runner is `go test ./internal/fixtax` (`TestLiveBaselineCorpus`). Escaped `$$` environment values are compared as engine **runtime** strings (`$VAR`), not as the dump's `$$VAR`. Default and alternate interpolation text expands recursively, up to depth eight. CLI `--env-file` / `COMPOSE_ENV_FILES` **replaces** the project `.env` for interpolation (`interpolation.corpus.envfile-replaces-dotenv`).

Resolution-stage logic is not changed here.

## Regression corpus

Repair-locked and historically tricky cases live under `fixtures/regression/`. Each engine-anchored `kind: regression` row declares a **verifiable** `rationale` (`type: compose-spec` or `docs` plus an `https://` URL). GitHub issue numbers are not invented. The runner is `go test ./internal/fixtax -run TestLiveRegressionCorpus`. Merge-sequence and escaped-literal rows are **guards**: they are catalogued `matched` and fail if those repairs regress.

`interpolation.regression.nested-default` (`${MISSING:-$OTHER}`) is live-pinned **matched**: ComposeLens expands `OTHER` inside the default as the engine does. Required-unset interpolation is catalogued `engine-error` (the official engine exits; ComposeLens reports `required-error` without fabricating a config).

## Platform corpus

Windows path, newline, encoding, and shell/command fixtures live under `fixtures/platform/`. Each engine-anchored `kind: platform` row declares a **verifiable** `rationale` (`type: compose-spec` or `docs` plus an `https://` URL). GitHub issue numbers are not invented. The runner is `go test ./internal/fixtax -run TestLivePlatformCorpus`. In-scope fields for this corpus include `volumes` (bind source/target) as well as the interpolation/command fields.

Catalog values use `{project}` for the project directory and `{sep}` for the host separator. `posixValue` supplies the Linux/macOS value when necessary: `.\rel` is a literal filename there. Backslashes are never rewritten. `{optional: TEXT}` accepts either presence or absence of an implied engine setting, such as `create_host_path=true` for a short bind; explicit `false` still differs. Coverage counts come from the catalog, while each engine disagreement fails its own fixture.

Honest recorded divergences (findings, not hidden, not “fixed”): relative bind sources stay relative in ComposeLens while the engine absolutizes them (**D1 by-design**, `differential` explains); shell-form `command`/`entrypoint` stay `form=shell` locally while the engine emits exec argv (**D2 by-design**, `differential` explains). Drive-letter binds, CRLF vs LF, UTF-8 with/without BOM, exec-form commands, and Windows-style exec argv **matched** live v5.4.0.

## Privacy / security corpus

Secret-shaped values and active-content fixtures live under `fixtures/security/` and are declared in `fixtures/catalog.yaml` (`kind: security`, with a verifiable `rationale`). Live secret probes are **in-process only** (`go test ./internal/fixtax -run TestSecurityCorpus`). Catalog files use demo placeholders so `ContainsSecretMaterial` does not reject the tree. Output surfaces (`inspect` / `explain` / `explain --all` / `diff` / `check` JSON+human+SARIF / `differential`) are checked for redaction and inertness. `report-xss` projects test HTML report escaping and JavaScript URLs rendered as text through `TestReportFixtureSafety`; their engine comparisons remain `pending-engine`. See `docs/security-corpus.md`.
