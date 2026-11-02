# GitHub Action

ComposeLens ships a **composite** GitHub Action (`action.yml` + `scripts/composelens-action.sh`) that builds the CLI **from this source tree** and runs `composelens check --github`. It is **not** a Marketplace listing and **not** a GitHub Release download (release binaries are later, not enabled). Enable `.github/workflows/example-composelens.yml` in your repository to run it.

The Action emits the same check findings as the CLI. Locations on GitHub workflow annotations come from the SARIF `physicalLocation` (project-relative `artifactLocation.uri` + `region.startLine`).

## What this is

| Piece | Role |
| --- | --- |
| `action.yml` | Composite metadata: inputs, outputs, `runs.using: composite` |
| `scripts/composelens-action.sh` | Wrapper used by GitHub-hosted runners (`shell: bash`) |
| `scripts/composelens-action.ps1` | Windows-local twin of that wrapper (local runs) |
| `.github/workflows/example-composelens.yml` | Example consumer workflow |
| `composelens check --github` | Tested CLI output mode (check-only; mutually exclusive with `--json` / `--sarif`) |

Doctor lists `github-action-live` as **deferred**, meaning live execution / Marketplace / API annotation, in the same way as `sarif-upload`: `check --sarif` writes SARIF locally and nothing is uploaded.

## Inputs

| Input | Default | Maps to |
| --- | --- | --- |
| `project-directory` | `.` | `--project-directory` |
| `files` | empty | repeatable `--file` (newline- or comma-separated) |
| `profiles` | empty | repeatable `--profile` |
| `policy` | empty | `--policy` (omitted when empty — empty `--policy=` is usage) |
| `redact` | empty | `--redact` (omitted when empty) |
| `fail-on` | `error` | wrapper env `COMPOSELENS_FAIL_ON` after a completed check: `error` (default gate), `warning`, `info`, `never` |
| `emit-json` | `true` | write `composelens-check.json` |
| `emit-sarif` | `true` | write `composelens-check.sarif` (local file; **not** an upload) |
| `emit-summary` | `true` | write `composelens-check.md` and append to `GITHUB_STEP_SUMMARY` when set |
| `emit-annotations` | `true` | print `::error` / `::warning` / `::notice` on the step log |

`fail-on` does **not** change `check --json` / `--sarif` / human exit codes. Usage, input, safety, and internal failures still fail the step.

## Outputs

`json-path`, `sarif-path`, `summary-path`, `exit-code`. An artifact path that is a symbolic link is refused (`output-exists`); the CLI never writes through a link.

## Build-from-source constraint

The wrapper runs `go build ./cmd/composelens` inside the Action checkout. Consumers must provide a Go toolchain (the example workflow pins `actions/setup-go` by full commit SHA). A first CI run may download `gopkg.in/yaml.v3` unless the module cache is already populated. Local verification uses `GOPROXY=off` with an existing module cache. **There is no release-binary download.**

## `check --github`

Stdout is GitHub workflow commands only:

```
::warning file=compose.yaml,line=<n>::CHK01 web:API_TOKEN: …
```

`file` and `line` come from the same source location as SARIF `physicalLocation`. SARIF URIs are relative to the selected `--project-directory`; annotation `file` is relative to `GITHUB_WORKSPACE` when it is set (else to the project directory). Outside policy: a file outside that base gets no file location (SARIF: no `physicalLocation`; annotation: no `file=`); it is never reduced to its basename. Paths use forward slashes — never `C:\Users\…`. Info findings use `::notice`. Waived findings are omitted from annotations and listed under a Waived heading in the Markdown summary.

Optional env (set by the wrapper):

| Env | Effect |
| --- | --- |
| `COMPOSELENS_JSON_PATH` | write check JSON (same bytes as `check --json` plus a trailing newline) |
| `COMPOSELENS_SARIF_PATH` | write SARIF (same bytes as `check --sarif` plus a trailing newline) |
| `COMPOSELENS_GITHUB_SUMMARY` | write the Markdown summary artifact |
| `GITHUB_STEP_SUMMARY` | append the same Markdown (GitHub-provided) |
| `COMPOSELENS_FAIL_ON` | `error` / `warning` / `info` / `never` |

Output is passed through `safety.Guard` and finding text through `redact.DisplayHuman`, which shows control characters as escapes. Secret values are not copied into annotations or the summary. Annotation data escapes `%`, CR and LF; in the summary every location, target, message and artifact name is a Markdown code span that its text cannot close, so a Compose key cannot inject links, images or Markdown blocks (`docs/privacy.md`).

## Example workflow

`.github/workflows/example-composelens.yml` is an example consumer workflow. Third-party actions are pinned by the same full SHAs as `.github/workflows/ci.yml` (`actions/checkout@3d3c42e5…`, `actions/setup-go@b7ad1dad…`). Enable those workflows in your repository.

## Pull-request annotations

The annotation format and its `file`/`line` match SARIF exactly (tested). GitHub shows them on a pull request once the example workflow is enabled in your repository.
