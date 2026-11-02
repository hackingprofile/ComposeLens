# Distribution (local CLI bundle)

ComposeLens ships as **one self-contained CLI binary**. This document describes what that bundle contains today. It is **not** a GitHub Release asset, signed artifact, CI matrix, or cross-compiled download (those remain later, not enabled).

## What the bundle contains

| Item | In the binary | Notes |
| --- | --- | --- |
| `composelens` executable | yes | `go build ./cmd/composelens` |
| HTML report viewer | yes | Generated in-process by `report --html` (CSS + boot script + JSON island compiled into the binary) |
| `composelens.report.v0` JSON Schema | yes | `go:embed` copy of `schemas/composelens.report.v0.json`; `$id` must stay `composelens.report.v0` |
| Nested graph/check/diff/differential schema **ids** | yes | Constants in those packages; no extra JSON Schema files |
| Development server | **no** | None exists and none is required |
| Repo tree / `schemas/` on disk | **not required at runtime** | Needed only to rebuild from source |
| Remote CSS/JS/fonts | **no** | Offline HTML; `RemoteRefs` fail-closed |
| Third-party notices | **ship next to the binary** | `THIRD_PARTY_NOTICES.md` (gopkg.in/yaml.v3 MIT + Apache-2.0 texts, Go BSD-3-Clause licence) with `LICENSE` and `NOTICE`; every binary distribution must carry them |

## How a consumer runs a report

From any directory that has a Compose project (and the `composelens` binary on `PATH` or next to the project):

```
composelens report --json --project-directory .
composelens report --html --project-directory .
```

Copying only the binary plus a `compose.yaml` into an empty folder is enough. No template directory, no `schemas/` checkout, no `localhost` viewer.

## Prepared vs shipped

**Prepared:** self-contained local binary; embedded schema; runs from an empty directory; no-dev-server regression guard.

**Not shipped here:** GitHub Release assets, checksums/signatures, Linux/macOS/Windows release matrices, installers. A composite Action interface exists (`docs/github-action.md`); enable the provided workflows in your repository.

## Report bytes

`report --json` / `--html` bytes are unchanged by packaging. Human-format identity labels do not alter the JSON/HTML package.
