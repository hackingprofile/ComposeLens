# CLI contract

This is the **frozen intended contract** for ComposeLens. Product version `0.1.0` implements `doctor`, `inspect`, `explain` (single-target and `--all` graph), `diff`, `check`, `differential`, `reproduce`, `report --json` (data package), `report --html` (interactive offline shell packaged in the binary), and `version`. `report` without `--json` or `--html` returns typed `unsupported` (human reserved).

Binary name: `composelens`.

## Global flags

These apply **only to the commands listed**. An inapplicable flag is **usage (exit 2)** with a typed message naming the flag and command, **before** any project load, engine call, or analysis. Empty stdout.

Project-reading commands: `doctor`, `inspect`, `explain`, `diff`, `check`, `differential`, `reproduce`, `report`.

| Flag | Repeatable | Commands | Meaning |
| --- | --- | --- | --- |
| `--project-directory <dir>` | no | project-reading | Project directory. Default (when omitted): first `--file`'s directory, else current working directory. Empty `--project-directory=` / missing value / value that looks like a flag is usage (exit 2). |
| `-f`, `--file <path>` | yes | project-reading | Compose files in **given order**. Disables default file discovery (including override auto-load). Paths are resolved from the current working directory. |
| `--env-file <path>` | yes | project-reading | Env files in **given order**. **Replaces** the project `.env` and **replaces** `COMPOSE_ENV_FILES` for interpolation (matching Docker Compose). Later `--env-file` overrides earlier. Not interpolated. |
| `--profile <name>` | yes | project-reading | Active Compose profiles. If any `--profile` is given, it **overrides** `COMPOSE_PROFILES`. |
| `--left-profile <name>` | yes | **`diff` only** | Left-side profiles. If any are given, they override `--profile` on the left. |
| `--right-profile <name>` | yes | **`diff` only** | Right-side profiles. If omitted, copies the left set. |
| `--left-env-file <path>` | yes | **`diff` only** | Left-side extra env-files. If any are given, they replace `--env-file` on the left. |
| `--right-env-file <path>` | yes | **`diff` only** | Right-side extra env-files. If omitted, copies the left list. |
| `--json` | no | `version`, `doctor`, `inspect`, `explain`, `diff`, `check`, `differential`, `reproduce`, `report` | Stable JSON on stdout. No extra prose on stdout. Mutually exclusive with `--sarif`, with `--github`, with `--html`, and with `--bundle`. |
| `--html` | no | **`report` only** | Self-contained interactive HTML of the report package on stdout (keyboard-navigable views). Mutually exclusive with `--json`. Zero remote assets (`docs/report.md`). |
| `--sarif` | no | **`check` only** | SARIF 2.1.0 on stdout. Local serialization; not an upload. Mutually exclusive with `--json` and with `--github`. |
| `--github` | no | **`check` only** | GitHub workflow annotations on stdout (`::error` / `::warning` / `::notice file=<path>,line=<n>::…`; `<path>` is relative to `GITHUB_WORKSPACE` when set, else to the project directory, and omitted for a file outside it). Local serialization for CI logs; not a GitHub API call and not a workflow run. Mutually exclusive with `--json` and with `--sarif`. See `docs/github-action.md`. |
| `--bundle <path>` | no | **`doctor` only** | Write a telemetry-free diagnostic bundle to `<path>` (`docs/support.md`). Environment/capability metadata only — Compose files are not read. Empty `--bundle=` / missing value / a following flag as the value is usage (exit 2). Mutually exclusive with `--json`. |
| `--policy <path>` | no | **`check` only** | Schema-validated policy overlay. Invalid policies fail before analysis (exit 3). Explicit empty `--policy=` / missing value / `--policy` followed by another flag is usage (exit 2) and does not run analysis. Policy files are bounded (1 MiB, depth 64, 50 000 nodes, one document) and charged against the shared invocation budget (`docs/policy.md`, `docs/limits.md`). |
| `--redact <path>` | no | project-reading | Schema-validated redaction overlay (`docs/redact.md`). Adds secret key/value patterns and specific allowlists. Invalid configs fail before analysis (exit 3). Empty / missing value is usage (exit 2). Bounded and charged like other untrusted files. If omitted, `composelens.redact.yaml` in the project directory is loaded when present. |
| `--all` | no | **`explain` only** | Whole-model provenance graph. Cannot be combined with a target. |
| `--no-engine` | no | **`report` only** | Run no Docker command; the differential section is `engineState: skipped` with `engineSkipReason`. Cannot be combined with `--allow-network`. |
| `--allow-short-secret <KEY>` | yes | **`inspect`, `explain`, `diff`, `check`, `differential`, `report`** | Repeatable, exact key name. Accept a secret value under KEY that is shorter than 6 bytes: it is not byte-scanned but stays withheld; prints a warning; JSON records `allowShortSecret`. Wildcards, lists and empty names are usage (exit 2). See `docs/privacy.md`. |
| `--allow-network` | no | **`report`, `differential`** | Allow the local `docker compose config` capture when the selection has a remote include (`oci://`, Git, `http(s)://`), which the engine resolves over the network. Without it that capture is skipped. |
| `-h`, `--help` | no | any | Help text on stdout, exit `0`. |
| `--` | no | any | **End of flags.** Remaining tokens are operands: the first is the command (if not already seen), then at most one `explain` target. `composelens -- version` runs `version`. A later operand on a command that takes none is usage (exit 2). Tokens after `--` are never parsed as flags (`composelens -- version --json` is an unexpected argument, not JSON mode). Flags before `--` still apply (`composelens --json -- version`). |

### Value contract

Every value-taking flag (`--project-directory`, `-f`/`--file`, `--env-file`, `--profile`, the four diff-only flags, `--policy`, `--redact`, `--bundle`) obeys the same rule:

- no following token → usage exit 2 (`missing value for FLAG`)
- next token looks like a flag (`--json`, `--`, `-f`, …) → usage exit 2; the following flag is **not** consumed as the value
- empty or whitespace-only (`--flag=` / `--flag ""`) → usage exit 2

Repeatable flags keep repeat semantics; each occurrence must satisfy the contract. A path that starts with `-` can be passed with `--flag=./-name`.

`COMPOSE_FILE` is honored when no `--file` is given. The list separator is `;` on Windows and `:` elsewhere (`os.PathListSeparator`). `COMPOSE_ENV_FILES` is **comma-separated** on every platform. Explicit `--env-file` replaces that predefined list.

## Commands

### `composelens version`

Prints product identity. Accepts **only** `--json` and `-h`/`--help`. Project/selection flags (`--project-directory`, `-f`/`--file`, `--env-file`, `--profile`, diff-only flags, `--sarif`, `--github`, `--bundle`, `--policy`, `--redact`, `--all`, `--html`, `--no-engine`, `--allow-network`) are usage (exit 2).

### `composelens doctor`

Reports platform, optional Docker Compose **detection** (version string only; no render), discovered inputs, and the feature support of this build. Implemented features include `fixture-taxonomy` (local catalog harness; not a `composelens fixtures` command — see `docs/fixtures.md`), `compose-engine-adapter` (invoke `docker compose version`/`config` with typed absent/error — see `docs/engineadapter.md`), `compose-engine-capability` (recognized Compose v2+ family vs verified pin v5.4.0 — see `docs/enginecap.md`), `compose-engine-differential` (`composelens differential` — see `docs/differential.md`), `compose-reproduction` (`composelens reproduce` — see `docs/reproduction.md`), `compose-policy-loading` (`check --policy` — see `docs/policy.md`), and `redaction-config` (`--redact` / `composelens.redact.yaml` — see `docs/redact.md`). Doctor JSON `engineCapabilities.support: "recognized"` means recognized v2+ family, not a verified matrix. `policy-engine` stays deferred. Doctor lists `sarif-upload` and `github-action-live` as **deferred** (SARIF upload; live Actions runs / Marketplace); local `check --sarif` / `--github` already serialize.

`doctor --bundle <path>` writes a support bundle (`composelens.support.bundle.v0`) that contains only environment/diagnostic metadata. It does not read the project and is mutually exclusive with `--json` so `doctor --json` stdout is unchanged. See `docs/support.md`.

### `composelens inspect`

**Source-level view — not resolved provenance.**

Reports:

- discovered Compose files in order (canonical path, digest, origin)
- services (name + YAML location)
- collected environment sources per key (stage, path, line, fingerprint, redacted value)
- interpolation-stage resolution for Compose-model strings that contain `$` (raw, resolved, source, typed state). Per-file, including files pulled in by `include:`, before merge. Not container-environment precedence.
- top-level `include:` expansion (include graph, nested includes, typed cycle/absent/depth). Included files are the base; the including file overrides. Long-form `env_file`/`project_directory` are not applied. See `docs/include.md`.
- service `extends` (mapping form `{service, file?}`): inherited vs overridden fields, relationship keys not copied, typed cycle/absent. String short form is unsupported. See `docs/extends.md`.
- multi-file merge after interpolation, include expansion, and extends (effective field, action, winning file, overridden contributors, include chain / extends origin when applicable). Sequences append (unique-key dedup / atomic replace per `docs/merge.md`). Not container-environment precedence.
- profile activation after merge (active set + source, per-service enabled/disabled + reason). See `docs/profiles.md`.
- container environment after profiles (`environment:` / `env_file:` winner + ordered losers). Distinct from interpolation. Dockerfile `ENV` and `run -e` are not applied. See `docs/containerenv.md`.
- canonical dual-form fields after merge (ports, volumes, labels, command/entrypoint representation, healthcheck.test). See `docs/normalize.md`.

Environment fingerprints are comparable **within one invocation only**. They are not stable across runs.

Does not emit a provenance graph. Interpolation uses documented interpolation precedence only; nested defaults and `.env` values are interpolated as Compose does (`docs/interpolation.md`). Merge rules are in `docs/merge.md`. Include rules are in `docs/include.md`. Extends rules are in `docs/extends.md`. Container-environment rules are in `docs/containerenv.md`. Normalization rules are in `docs/normalize.md`.

Scope: source-level view + interpolation engine + `include:` expansion + service `extends` + multi-file merge + service profiles + container-environment precedence + canonical dual-form normalization.

### `composelens explain`

**Single-target account composed from existing stage provenance.** With `--all`, a **whole-model provenance graph** (`docs/graph.md`).

Without `--all`, requires exactly one target:

- service: `web`
- field: `services.web.image` (or `services.web.api.image` for a dotted service name)
- container-environment variable: `web:COLOR` (`service:VAR`)

Prints the applicable stages in resolution order (interpolation → include → extends → merge → profiles → container-environment), ending at the final effective value. Stages that do not apply are omitted. A nonexistent target is typed `absent` with an empty stage list. Missing target (and no `--all`) is usage (exit 2). Secrets stay redacted. See `docs/explain.md`.

`--all` assembles every effective service/field/variable into `composelens.graph.v0` with shadow-chains. `--all` plus a target is usage. See `docs/graph.md`.

`--json` schema: `composelens.explain.v0` (single target) or `composelens.graph.v0` (`--all`). Inspect JSON is unchanged.

Scope: composition of interpolation through container-environment provenance; `--all` is the provenance graph.

### `composelens diff`

**Effective-config delta over the same Compose files — not a provenance graph, not an engine differential.**

Compares two selections (`--left-profile` / `--right-profile`, optional `--left-env-file` / `--right-env-file`). Both sides run the existing interpolation → include → extends → merge → profiles → container-environment pipeline. Reports services added/removed (enabled/disabled), fields and container-env vars added/removed/changed, with each side's winning source. Dual-form fields (ports, volumes, labels, command, entrypoint, healthcheck.test) compare as canonical values (`docs/normalize.md`). Identical selections produce an empty diff. Secrets that differ are changed-by-presence with values redacted. Comparing two different file sets is deferred. See `docs/diff.md`.

`--json` schema: `composelens.diff.v0`. Explain JSON is unchanged. Inspect JSON does not gain diff fields (it does gain additive `normalization` keys; see `docs/normalize.md`).

Scope: comparison of two pipeline runs; not an engine differential.

### `composelens check`

**Fixed ruleset over existing stage provenance — not a general policy engine, not a provenance graph.**

Runs CHK01–CHK06 (`docs/check.md`) over the same pipeline as `inspect`. Optional `--policy <file>` loads a schema-validated overlay (`docs/policy.md`); invalid policies fail before analysis (exit 3). Explicit empty `--policy=` or `--policy` followed by another flag is usage (exit 2) before analysis. Without `--policy`, the fixed ruleset **findings** are unchanged; `check` now exits **`6`** (`Assertion`) when a remaining finding meets the severity gate (default `error`). Warning- and info-only results still exit `0`. Emits human (default), JSON (`--json`, schema `composelens.check.v0`), SARIF 2.1.0 (`--sarif`), or GitHub workflow annotations (`--github`). The serializations agree on the finding set, waived state, and gate. `--json`, `--sarif`, and `--github` are pairwise mutually exclusive (usage, exit 2). SARIF is validated locally only; there is no upload. `--github` is a local log format for GitHub Actions (`docs/github-action.md`); it is not a CI run.

Scope: fixed six-check ruleset plus optional policy overlay; not a general policy engine.

### `composelens differential`

**Internal effective model vs live `docker compose config` — not a stage fix, not engine parity.**

Captures `docker compose config` through the engine adapter, canonicalizes dual-form fields on both sides (`docs/normalize.md`), and emits `match` / `divergent` / `only-internal` / `only-engine` / `uncertain` rows. Divergences are the finding. Secret rows are fingerprint-compared when both raw values exist (display stays `[redacted]`; hashes are never emitted); a withheld placeholder is typed uncertainty, not a proven match. Only-internal / only-engine stay presence facts. Engine-absent yields a typed empty row set. See `docs/differential.md`.

`--json` schema: `composelens.differential.v0`.

Scope: honest comparison; resolution stages unchanged.

### `composelens reproduce`

**Exact `docker compose … config` command that recreates the modeled configuration — files and flags only.**

Prints a deterministic, ordered invocation from the same `--project-directory`, `-f`, `--env-file`, and `--profile` / `COMPOSE_PROFILES` selection ComposeLens used. The human `command` string is POSIX-single-quote-safe for copy-paste; `argv` is the canonical token list (live validation executes `argv`, not the shell line). It does not run the engine. A live test that running the command matches the model is described in `docs/reproduction.md`. Secret values are never inlined; secret-shaped profile names fail closed.

`--json` schema: `composelens.reproduce.v0` (`argv` + `command`).

Scope: command generation; not a differential.

### `composelens report`

**JSON data package or interactive offline HTML — not a hosted viewer.**

`report --json` emits `composelens.report.v0`. `report --html` emits one self-contained HTML file that inlines that package as inert JSON and paints four keyboard-navigable views: provenance graph + shadow-chains, source chain, diff/differential, and diagnostics. Primary journeys J1–J4 complete by keyboard alone. The shell meets a WCAG 2.1 AA structural pass: accessible names, landmarks/headings, skip link, numeric AA contrast, reduced-motion guard, per-view screen-reader summaries, and a polite `aria-live` region (`docs/report.md`). CSP is a restrictive offline policy (hash-pinned scripts/styles, no network origin, no `unsafe-eval`). Package values never become URL/event sinks. HTML over 4 MiB fails as `input-total-too-large` (exit 3).

Without `--json` or `--html`, the human report is **unsupported** (exit `5`). `--json` and `--html` together, or `--json` and `--sarif`, are usage (exit `2`). `--policy` and `--all` stay invalid on `report`.

Scope: JSON package + interactive, accessible, CSP-hardened offline HTML. The HTML viewer is compiled into the CLI binary (`docs/distribution.md`). Signed release binaries and cross-builds are not provided.

## Stdout / stderr

| Stream | Rule |
| --- | --- |
| stdout | Human report, JSON (`--json`), HTML (`--html` on `report`), SARIF (`--sarif` on `check`), GitHub workflow commands (`--github` on `check`), or help. `doctor --bundle` writes a file and leaves stdout empty. |
| stderr | Errors, safety failures, warnings |
| `--json` | stdout is one JSON document only |

JSON field order follows Go struct order. Env keys are sorted by name. File and service lists keep discovery / YAML order.

Failure JSON (`composelens.error.v0` on stderr) includes `code`, `remediation`, and `doc` from the diagnostics catalog (`docs/diagnostics.md`). Human stderr prints the same fields. Exit codes are unchanged.

Secrets never appear in either stream. Parse and dispatch failures (unknown flags, unknown commands, unexpected arguments, missing `--file` / `--env-file` paths) never echo flag values or secret-shaped user text; they name the flag without a value, use `<redacted>`, or keep a safe path when the name is not secret-shaped. Usage failures still use exit `2` and write to stderr with empty stdout. Input-not-found failures still use exit `3`, including a `--project-directory` that does not exist (`project-directory-missing`, every project command) and, for `check`, a project with no Compose file (`no-compose-file`).

## Exit codes

| Code | Name | When |
| --- | --- | --- |
| `0` | Success | Command completed; doctor may still report engine `absent` |
| `2` | Usage | Bad flags, missing command, help-ineligible misuse, inapplicable flag, empty/missing flag value, flag consumed as a value, unexpected operand after `--` |
| `3` | Input | Explicit `--file` / `--env-file` / `--policy` not readable; unparseable Compose; **invalid policy** (no analysis) |
| `4` | Safety | Output guard failed closed (possible secret leak, uncertain safety, or fingerprint-key generation failed) |
| `5` | Unsupported | Command or requested mode not implemented in this version |
| `1` | Internal | Unexpected failure. Stderr adds telemetry-free crash guidance and how to write `doctor --bundle` (`docs/support.md`). A recovered panic in `main` uses the same exit and does not print the panic value. |

`inspect` with no Compose files discovered (defaults) exits `0` and reports files as `absent`. An **explicit** missing `--file` exits `3`. Unparseable or bound-exceeding input (hostile YAML, oversized file, aggregate/file-count/engine-output cap, invalid encoding) also exits `3` with a typed diagnostic (`docs/parser.md`, `docs/limits.md`). `explain` with no target exits `2`. A nonexistent explain target exits `0` with `state: absent`. `check` exits `6` when a remaining finding meets the severity gate (default `error`); warning/info-only and clean results exit `0`. `differential` with divergences exits `0`. `report --json` and `report --html` exit `0` when the document is written (check assertion is payload, not this exit). `report` without `--json` or `--html` exits `5`. `--json` together with `--sarif`, `--github`, `--bundle`, or `--html` exits `2`.

## Doctor JSON (`composelens.doctor.v0`)

Stable keys: `schema`, `product`, `version`, `platform`, `engine`, `engineCapabilities`, `inputs`, `features`, `evidence`.

`engine.state` is `known`, `absent`, or `unknown`. Detection does not imply render capability. `engineCapabilities` is the engine capability map (`docs/enginecap.md`): a parsed Compose plugin major ≥ 2 is the **recognized** family (`support: "recognized"` in JSON); the **verified** pin is Docker Compose v5.4.0 / Engine 29.7.2. Unverified engine behaviors are `unknown`. Doctor does not run `docker compose config`.

## Inspect JSON (`composelens.inspect.v0`)

Stable keys: `schema`, `product`, `version`, `view`, `disclaimer`, `files`, `services`, `environment`, `interpolationDisclaimer`, `interpolation`, `includesDisclaimer`, `includes`, `extendsDisclaimer`, `extends`, `mergeDisclaimer`, `merge`, `profilesDisclaimer`, `activeProfiles`, `profileServices`, `containerEnvironmentDisclaimer`, `containerEnvironment`, `evidence`.

`view` is always `source-level`. `disclaimer` is exactly:

`source-level view — not resolved provenance`

Environment entries use `evidence: "unresolved"`.

## Explain JSON (`composelens.explain.v0`)

Stable keys: `schema`, `product`, `version`, `disclaimer`, `target`, `state`, `stages`, `effective`, `secret`, `finalStage`, `certainty`, `evidence`.

`disclaimer` is:

`single-target account composed from existing stage provenance — not a provenance graph`

Inspect JSON does not include these keys.

## Graph JSON (`composelens.graph.v0`)

Stable keys: `schema`, `product`, `version`, `disclaimer`, `nodes`, `counts`, `evidence`, `certainty`.

`disclaimer` is:

`whole-model provenance graph assembled from existing stage outputs — not a new resolver, not an engine differential`

Emitted only by `explain --all --json`. Inspect and single-target explain JSON do not include these keys. Graph nodes are unique by `(kind, target)`; a CLI string that matches more than one entity stays `absent` on single-target `explain`.

## Diff JSON (`composelens.diff.v0`)

Stable keys: `schema`, `product`, `version`, `disclaimer`, `left`, `right`, `changes`, `empty`, `evidence`, `certainty`.

`disclaimer` is:

`effective-config delta over the same Compose files — not a provenance graph, not an engine differential`

Inspect and explain JSON do not include these keys.

## Check JSON (`composelens.check.v0`)

Stable keys: `schema`, `product`, `version`, `disclaimer`, `ruleset`, `findings`, `counts`, `evidence`, `certainty`. Optional `policy` is the schema id when `--policy` was applied.

`disclaimer` without `--policy` is:

`fixed ruleset over existing stage provenance — not a policy engine, not a provenance graph`

With `--policy` it is:

`schema-validated policy overlay on the fixed ruleset — not a general policy engine`

SARIF (`--sarif`) is a SARIF 2.1.0 document, not this schema. `--github` is GitHub workflow commands plus optional side-files (`docs/github-action.md`), not this schema. Inspect, explain, and diff JSON do not include check keys.

## Differential JSON (`composelens.differential.v0`)

Stable keys: `schema`, `disclaimer`, `engineState`, `engineVersion`, `engineCommand`, `projectDirectory`, `rows`, `summary`, `evidence`, `certainty`.

`disclaimer` is:

`internal model vs live docker compose config — divergences are findings, not a claim of engine parity; not a stage fix`

Inspect, explain, diff, and check JSON do not include these keys.

## Reproduce JSON (`composelens.reproduce.v0`)

Stable keys: `schema`, `product`, `version`, `disclaimer`, `argv`, `command`, `projectDirectory`, `files`, `envFiles`, `profiles`, `evidence`, `certainty`.

`disclaimer` is:

`exact docker compose config invocation that recreates the modeled configuration — files and flags only; not an engine differential`

Inspect, explain, diff, check, and differential JSON do not include these keys.

## Report JSON (`composelens.report.v0`)

Stable keys: `schema`, `product`, `version`, `disclaimer`, `determinism`, `generatedBy`, `source`, `graph`, `check`, `diff`, `differential`, `diagnostics`, `evidence`, `certainty`.

`disclaimer` is:

`self-contained JSON report data package assembled from inspect, explain --all, check, diff, and differential — not an HTML viewer, not a new resolver`

`determinism` is `byte-stable-v0`. Nested `graph` / `check` / `diff` / `differential` keep their existing schema ids. See `docs/report.md`. `report --html` embeds this document inertly; it is not a second schema.

## Version JSON (`composelens.version.v0`)

Stable keys: `schema`, `name`, `version`.
