# Check

`composelens check` runs a **fixed, documented** five-check ruleset over the already-resolved effective model. Optional `check --policy <file>` loads a schema-validated overlay (`docs/policy.md`) with the same 1 MiB / depth / node bounds as the Compose parser, one document only, and lexicographic unknown-field order. Without `--policy`, behavior is unchanged. It is analysis, not a new resolver and not a general policy engine.

`inspect`, `explain`, and `diff` stay unchanged in meaning. Check is additive.

## Ruleset (`fixed-v0`)

| ID | Name | Severity | Fires when |
| --- | --- | --- | --- |
| CHK01 | `secret-inline` | warning | A secret-keyed or secret-looking value is **the effective (winning) value** and was **defined in the Compose model**: a direct literal, an interpolation default that was applied (`${VAR:-secret}` / `${VAR-secret}` when the variable did not supply the value), or a winning overlay literal. Advises an external secret. **Never reveals the value.** A `${VAR}` / `$VAR` reference whose effective value comes from the host or `.env` is **not** this check. A secret-shaped default that is **not** effective (the variable is set) is **not** this check. |
| CHK02 | `required-unset` | error | A `${VAR:?…}` / `${VAR?…}` required interpolation is in the interpolation `required-error` state. ComposeLens does not fabricate a value. |
| CHK03 | `profiled-dependency-gap` | warning | An enabled service `depends_on` a target gated behind an inactive profile (`ImplicitOf` set and the target is not enabled). Ordinary profile-disabled services with no such dependency are not this check. |
| CHK04 | `missing-target` | error | `include:` or mapping-form `extends` points at an **absent** file or service (`absent`). Cycle, unsupported, and depth states are **not** this check. |
| CHK05 | `env-shadowing` | info | A container-environment variable is `set` with at least one lower-precedence loser (`Overridden`). |
| CHK06 | `compose-rejects` | error | The input is one `docker compose config` refuses: an unknown top-level key (a typo such as `servics`; Compose accepts `version`, `name`, `include`, `services`, `networks`, `volumes`, `configs`, `secrets`, `models` and `x-` extensions), a `name` or `version` that is not a string, an interpolation in state `invalid-format` (`${A:0:2}`, `${}`), an `include:` that is not a list, or an include or extends cycle. ComposeLens still models what it can, but a gate does not pass a file the engine will not load. |

`check` also refuses, with exit **3**, a project directory that does not exist (`project-directory-missing`) and a project with no Compose file (`no-compose-file`): a gate never passes an empty or missing project. The GitHub Action fails the same way whatever its `fail-on` input.

Each finding carries: check id, severity, target, message, and provenance drawn from existing stage / `explain` inputs. Where a check cannot decide, it stays silent or carries certainty `unknown` — it does **not** false-positive.

Disabled (profile-gated) services are outside the effective model for CHK01 / CHK02 / CHK05.

## Output

One shared findings model is serialized four ways. The finding set (id + severity + target) **must agree**, including waived findings.

| Mode | Flag | Schema / form |
| --- | --- | --- |
| human | (default) | Severity-grouped list |
| JSON | `--json` | `composelens.check.v0` |
| SARIF 2.1.0 | `--sarif` | OASIS SARIF 2.1.0 document, validated locally |
| GitHub | `--github` | Workflow commands on stdout (`::error` / `::warning` / `::notice file=<repo-relative>,line=<n>::…`); optional JSON/SARIF/Markdown side-files via env (`docs/github-action.md`) |

`--json`, `--sarif`, and `--github` are pairwise mutually exclusive (usage, exit 2). `--sarif` and `--github` are valid only with `check`.

When remaining findings meet the severity gate (exit 6), human and JSON include catalog fields `code: exit.assertion`, `remediation`, and `doc` (`docs/diagnostics.md`). SARIF finding payloads are unchanged. Exit codes are unchanged.

SARIF is **produced and validated locally only**. There is no upload, no GitHub code-scanning integration, and no CI execution. `--github` is the same local-only rule: it prints workflow commands for a CI log; it does not call the GitHub API. Doctor lists `sarif-upload` and `github-action-live` as deferred: SARIF **upload** / code scanning and **live** Actions runs / Marketplace. The local serializations (`--sarif`, `--github`, `action.yml`) are implemented.

JSON field `secret: true` means the finding concerns secret-classified material. The value itself is omitted from every format.

SARIF `locations[]` keeps the existing `logicalLocations` entry (`fullyQualifiedName` = finding target). Each result also carries a **`physicalLocation`** when the model already has a source file: `artifactLocation.uri` is **project-relative with forward slashes** (never an absolute machine path, never `file://`). `region.startLine` (and `startColumn` when known) is the winning source line, matching `inspect`'s interpolation `File:Line` (or the container-environment winner line for a literal). Multi-file overlays point at the **winning** file. If the file is known but no precise line exists (for example an absent `include:`), `uri` is emitted and `region` is omitted — lines are never invented.

## Exit codes

`check` uses the existing table (`docs/cli.md`) plus a dedicated assertion code:

| Code | When |
| --- | --- |
| `0` | Check completed with **no remaining finding at or above the gate** (default gate: `error`). Warning- and info-only results exit 0. Waived findings do not gate while the exception is unexpired. |
| `2` | Usage (`--json` with `--sarif` or `--github`, `--sarif`/`--github`/`--policy` on another command, empty/missing `--policy` value, bad flags) |
| `3` | Input (explicit missing `--file`, unparseable Compose, **invalid `--policy`**) |
| `4` | Fail-closed output guard |
| `5` | Not used by `check` (human `report` without `--json`/`--html` still uses this code) |
| `6` | **Assertion** — at least one non-waived finding meets the gate severity (`internal/exitcode.Assertion`) |
| `1` | Internal encode/write failure |

Without `--policy`, the CHK01–CHK06 finding set is unchanged; only the process status is now meaningful for `error`-severity findings (CHK02, CHK04, CHK06). A policy may set top-level `gate` to `error` (default), `warning`, or `info`.

Waived findings stay in human, JSON (`waived: true`), and SARIF (`suppressions` with `kind: external`) with SARIF physical locations. They are not silently dropped.

## Secrets

Redaction uses `internal/redact`. The fail-closed output guard applies to human, JSON, and SARIF. Synthetic secret probes run in-process and are not stored with test evidence.

## Not this command

- Custom policy *rules* (new check ids). `--policy` overlays CHK01–CHK06 only (`docs/policy.md`)
- A `threshold` field (not in `composelens.policy.v0`; unknown field)
- HTML report
- SARIF **upload** / GitHub code-scanning / CI execution
- Engine differential
- Any change to interpolation–container-environment resolution, explain, or diff semantics

The provenance graph is `explain --all` (`docs/graph.md`), not `check`.
