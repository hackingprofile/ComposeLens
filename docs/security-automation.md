# Security automation

ComposeLens includes GitHub security-automation workflows in `.github/workflows/`. Enable them in your repository; required status checks and branch protection are repository settings (below).

`.github/workflows/ci.yml` and `.github/workflows/example-composelens.yml` are provided the same way.

## Workflows

| File | Purpose | Triggers | `permissions` | Pinned actions |
| --- | --- | --- | --- | --- |
| `codeql.yml` | CodeQL for Go | push/PR to `main`, weekly cron | `actions: read`, `contents: read`, `security-events: write` | `actions/checkout@3d3c42e5…` (from `ci.yml`); `github/codeql-action/{init,autobuild,analyze}@9b325408…`, one version for all three steps |
| `dependency-review.yml` | PR dependency review | pull_request to `main` | `contents: read` | `checkout@3d3c42e5…`; `actions/dependency-review-action@a1d282b3…` |
| `secret-scan.yml` | Gitleaks | push/PR to `main` | `contents: read` | `checkout@3d3c42e5…`; `gitleaks/gitleaks-action@e0c47f4f…` |
| `license-scan.yml` | License-eye header + dependency | push/PR to `main` | `contents: read` | `checkout@3d3c42e5…`; `setup-go@b7ad1dad…` (Go 1.27.3, the release in `go.mod`); `go run github.com/apache/skywalking-eyes/cmd/license-eye@v0.9.0` (module-versioned; not the composite actions, whose dependency action runs `actions/setup-go@v6`) |
| `scorecard.yml` | OpenSSF Scorecard | push to `main`, weekly cron | `contents: read` (results are not published and no step uploads SARIF) | `checkout@3d3c42e5…`; `ossf/scorecard-action@2d114668…` (`publish_results: false`); the action runs its container image `ghcr.io/ossf/scorecard-action:v2.4.4` by tag, not by digest |

Every `uses:` is a **full 40-hex-char commit SHA**, every `go run` names a released module version, and write permissions are granted only where a step uses them (checked by `TestWorkflowsPinnedAndLeastPrivilege`). Readable tags in comments are not pins. A top-level SHA does not pin what an action runs underneath; nested references of the actions above were checked, except the Scorecard container image, which is referenced by tag. Checkout/setup-go SHAs match `.github/workflows/ci.yml`. Other SHAs follow the same comment-tag style.

Every `actions/checkout` step sets `persist-credentials: false`, so later steps cannot reuse the job token from the git config. `run:` scripts take no `${{ }}` expressions; values reach them through `env:` (checked by `TestWorkflowHygiene`).

`actions/checkout` v7.0.1 and `actions/setup-go` v7.0.0 run on Node 24. When updating an action, move every workflow to the same new SHA, and bump the three CodeQL steps (`init`, `autobuild`, `analyze`) together. `ci.yml` runs golangci-lint v2.15.0 through `golangci/golangci-lint-action` v9.3.0 (pinned by commit SHA); `.golangci.yml` is in the version 2 format, which v7 and later of that action require.

Header and dependency licence policy lives in `.licenserc.yaml` (Apache-2.0 as shipped in `LICENSE` / `NOTICE`; `header.comment: never`). Every Go file under `cmd/` and `internal/` starts with `// SPDX-License-Identifier: Apache-2.0`; `license-eye header check` checks those files in `license-scan.yml`, and `TestGoSourcesCarryLicenseHeader` checks the same rule on every platform. Credential scanning uses `.gitleaks.toml` on top of the default Gitleaks rules.

### Secret-scan allowlist

The Go tests carry synthetic values with GitHub token prefixes and token-length suffixes to check that redaction withholds them. `.gitleaks.toml` allow-lists each probe by its exact anchored value, for its own rule (`github-pat`, `github-oauth`, `github-fine-grained-pat`), and only in Go test files under `internal/`. The generic API-key rule, whose matches on assignment-shaped test fixtures differ between Gitleaks releases, is allow-listed for those test files by path. A real token, any other value, or a probe value outside a test file still fails the scan. `TestGitleaksAllowlistCoversSyntheticProbes` fails when a test adds a value that the allowlist does not name. `TestSyntheticTokensStayInAllowedTestFiles` checks that credential-shaped examples do not appear in other public files, except their scanner configuration definitions.

## Required status checks / branch protection

When protection is enabled on the default branch (`main`), that protection **should require** these checks to pass before merge (names as GitHub reports them from the job `name:` fields):

- `test (ubuntu-latest)`, `test (macos-latest)`, `test (windows-latest)` (`.github/workflows/ci.yml` matrix)
- `analyze` (CodeQL)
- `dependency-review`
- `gitleaks`
- `license-eye`
- `scorecard`

Enable the workflows, then enable those required checks on the protected branch. CodeQL code-scanning upload, dependency review and Scorecard need features GitHub provides for public repositories (or GitHub Advanced Security on private ones).

## Local checks (install nothing)

- Credential hygiene: `gitleaks detect` with `.gitleaks.toml`, or a working-tree scan for `ghp_`, `gho_`, `github_pat_`, `AKIA`, `xox[baprs]-`, `-----BEGIN`, PEM markers, and connection-string `password=` forms.
- Licence inventory: `license-eye` with `.licenserc.yaml`, or `go.mod` / `go.sum` modules vs `LICENSE` files in the module cache.
