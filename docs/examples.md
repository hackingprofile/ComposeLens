# Adoption examples (monorepo and multiple projects)

Copy-pasteable ComposeLens invocations for (a) a **monorepo** of apps that each own a Compose file, and (b) **two independent** Compose projects. These trees live under `examples/monorepo/` and `examples/multi-project/`. Existing `examples/*-lab` directories are unchanged.

Placeholder/demo values only (`APP_ENV: demo`, colors). **No real secrets.**

## Local runner (the “examples execute in CI” bar)

CI workflows are provided under `.github/workflows/`; enable them in your repository. The examples meet this bar:

```
go test ./internal/adoption -count=1
```

That test runs **every command listed below** (same flags, from the repository root) and asserts the expected exit plus a key output fact. `scripts/run-adoption-examples.ps1` is a human-facing twin that needs a built `composelens` binary.

Enable `.github/workflows/` in your repository if you want these examples on pull requests.

Build once from the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
```

Unix: `go build -o composelens ./cmd/composelens`. Commands below use `composelens`; on Windows run `.\composelens.exe` with the same flags.

## Monorepo (`examples/monorepo`)

Each app is a separate Compose project. Optional overlay is a second `--file`, not a second engine.

| # | Invocation | Exit | Key output fact |
| --- | --- | --- | --- |
| M1 | `doctor --json --project-directory examples/monorepo/apps/web` | 0 | `"schema": "composelens.doctor.v0"` |
| M2 | `inspect --json --project-directory examples/monorepo/apps/web` | 0 | service `web` |
| M3 | `check --json --project-directory examples/monorepo/apps/web` | 0 | `"total": 0` |
| M4 | `inspect --json --project-directory examples/monorepo --file examples/monorepo/apps/web/compose.yaml --file examples/monorepo/overlays/shared.yaml` | 0 | `SHARED_FLAG` |
| M5 | `check --json --project-directory examples/monorepo/apps/api` | 0 | `"total": 0` (api is profile-gated without `--profile`) |
| M6 | `inspect --json --profile debug --project-directory examples/monorepo/apps/api` | 0 | service `api` |

## Multiple independent projects (`examples/multi-project`)

Do **not** combine `shop` and `billing` with multi-`--file`. Two directories, two invocations.

| # | Invocation | Exit | Key output fact |
| --- | --- | --- | --- |
| P1 | `inspect --json --project-directory examples/multi-project/shop` | 0 | service `shop` |
| P2 | `check --json --project-directory examples/multi-project/shop` | 0 | `"total": 0` |
| P3 | `inspect --json --project-directory examples/multi-project/billing` | 0 | service `billing` |
| P4 | `check --json --project-directory examples/multi-project/billing` | 0 | `"total": 0` |

## Diagnostic bundle (not an adoption example)

Support metadata is `doctor --bundle` (`docs/support.md`). It is not listed here because it is not a project-analysis example.
