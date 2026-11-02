# Contributing to ComposeLens

Thank you for considering a contribution.

## Local development

1. Install Go 1.27.3, the release `go.mod` names (see `docs/compatibility.md`). Docker CLI with the Compose plugin runs the live engine tests in `go test ./...` (without it they skip, or fail when `COMPOSELENS_REQUIRE_DOCKER=1`). The CLI itself still runs without Docker (`docs/quickstart.md`).
2. From the repository root:

```bash
go test ./...
go build -o composelens.exe ./cmd/composelens
```

3. Run `golangci-lint run ./...` with golangci-lint v2.15.0, the release CI pins (`.golangci.yml` is in the version 2 format), if the linter is available.
4. Do not add secrets to fixtures, snapshots, logs, or docs. Tests that need secret *values* must generate them at runtime in a temp directory.

## Evidence we ask for

Bug reports and pull requests should include **reproducible evidence**:

- Exact command(s) run
- Compose file names and whether they can be attached (redact secrets)
- `composelens doctor --json` output
- Expected vs actual (typed states: `known`, `absent`, `unresolved`, `conflict`, `unsupported`)
- Platform (`GOOS`/`GOARCH`, shell)

Do not paste raw secret values. If a value is secret, report only the key name, source path/line, and fingerprint.

## Pull requests

- Open PRs against `main`.
- Fill in `.github/pull_request_template.md`.
- Keep changes reviewable; do not mix unrelated refactors with behavior changes.
- Public contracts (`docs/cli.md`, JSON schemas, exit codes) require an explicit changelog note.

Suggested required status checks once branch protection is enabled in your repository:

- `ci / test (ubuntu-latest)`, `ci / test (macos-latest)` and `ci / test (windows-latest)` — `.github/workflows/ci.yml` builds, tests and lints on Linux, macOS and Windows; the Linux leg also runs the race detector (`docs/compatibility.md`).
- The security workflows' checks listed in `docs/security-automation.md` (`analyze`, `dependency-review`, `gitleaks`, `license-eye`, `scorecard`).

Docker-dependent live tests skip without a Docker CLI on PATH. The Linux and Windows legs set `COMPOSELENS_REQUIRE_DOCKER=1`, so there they must run; the macOS runner has no Docker CLI, so they skip with that reason (`docs/quickstart.md`). Live tests accept the installed Compose release and log it. Lint is part of the `ci` job (golangci-lint v2.15.0). Enable the workflows under `.github/workflows/` in your repository.

## Code of conduct

Participation is governed by `CODE_OF_CONDUCT.md`.

## Licence

Contributions are under Apache-2.0. See `LICENSE` and `NOTICE`.
