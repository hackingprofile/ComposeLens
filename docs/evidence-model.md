# Evidence model

ComposeLens reports **what it actually observed**, with explicit uncertainty. It never invents a Compose value.

## Presence

Every interesting fact is tagged with one presence state:

| State | Meaning |
| --- | --- |
| `known` | Observed and parsed in this run |
| `absent` | Looked for and not found (for example, no Compose file, no Docker CLI) |
| `unresolved` | Observed inputs exist but this inspect view does not compute the effective winner |
| `conflict` | Reserved for later versions when two sources disagree after resolution rules |
| `unsupported` | A real Compose/CLI feature this version does not implement |

`inspect` **source-level** environment keys remain **`unresolved`**: collected `.env` / allowlist / `--env-file` sources are labeled, not ranked as a container winner. Interpolation-stage results on Compose-model strings are **`known`** for that stage only. Include-graph rows are **`known`** when a path loaded, **`absent`** when the included file was missing, and **`unsupported`** for unapplied long-form extras or bounded-depth refusal; a cycle is a typed `cycle` state. Extends-graph rows are **`known`** when mapping-form inheritance applied, **`absent`** when the target file/service is missing, **`unsupported`** for string short form, and a cycle is a typed `cycle` state. Multi-file merge fields are **`known`** for the merge-stage rules in `docs/merge.md`. Profile activation is **`known`** for the rules in `docs/profiles.md` (not engine-resolved provenance). Container-environment rows are **`known`** for `environment:` / `env_file:` / host-shell pass-through as documented in `docs/containerenv.md`; Dockerfile `ENV` is `unsupported`. Canonical dual-form items are **`known`** when the conversion is documented and parsed; otherwise **`unknown`/`unsupported`** (`docs/normalize.md`). `conflict` is not emitted for env keys.

## Certainty

| State | Meaning |
| --- | --- |
| `proven` | Derived from bytes or process state this process read |
| `inferred` | Detection based on a heuristic rather than direct observation (example: shell name from environment variables) |
| `unknown` | Not determined; do not guess |

File digests, YAML line/column, and env file line numbers are `proven` when the file was read. Host-shell allowlist values are `proven` as "present in this process environment", which is **not** a claim that `docker compose` would use them the same way (`unresolved` for engine effect).

## Vocabulary (source / stage / provenance)

- **Source** — a concrete origin: a file path, a line, a flag, `COMPOSE_FILE`, or the host-shell allowlist.
- **Stage** — env collection bucket: `project-env`, `env-file`, `host-shell`. Interpolation uses those stages with interpolation precedence (shell > env-file, which **replaces** `.env` when `--env-file` / `COMPOSE_ENV_FILES` is set; otherwise project `.env`). Container environment uses `environment`, service `env_file`, and named host-shell pass-through (`docs/containerenv.md`).
- **Provenance** — the full winner/shadow/reproduction graph. `explain --all` emits a whole-model graph assembled from existing stage outputs (`docs/graph.md`); it is not a new resolver. Inspect remains a source-level view, including an additive canonical-normalization section (`docs/normalize.md`). `explain <target>` composes those existing per-stage results for one target (`docs/explain.md`). `diff` compares two pipeline runs over the same files (`docs/diff.md`); dual-form fields compare as canonical values; it is not an engine differential. `check` runs a fixed ruleset over that same model (`docs/check.md`); it is not a policy engine. The fixture harness (`docs/fixtures.md`) reports local assertions; interpolation/precedence baseline rows are live-pinned (`docs/corpus.md`). Other engine results stay `pending-engine`. The engine adapter (`docs/engineadapter.md`) captures redacted `docker compose config` when Docker is present. `composelens differential` (`docs/differential.md`) compares the internal model to that capture; divergences are findings, not a claim of engine parity. `composelens reproduce` (`docs/reproduction.md`) prints the file/flag `docker compose … config` command that recreates that selection.

Fingerprints on environment sources are **invocation-scoped**: equal values in one `inspect`/`doctor` report share an `hmac-sha256:` fingerprint; independent runs generate a new random HMAC key and will not match. Fingerprints are not a global identifier and must not be treated as stable across processes.

`composelens differential` secret rows are a different mechanism: when both raw values are available, the comparator uses a process-local SHA-256 fingerprint of each side and never emits that hash. Equal fingerprints are `match`/`proven`; different fingerprints are `divergent`/`proven`. A withheld `[redacted]` placeholder is `uncertain`/`unknown`. Inspect HMAC fingerprints must not be reused for this comparison.

## Schema names

JSON reports carry a `schema` string:

- `composelens.version.v0`
- `composelens.doctor.v0`
- `composelens.inspect.v0`
- `composelens.explain.v0`
- `composelens.graph.v0`
- `composelens.diff.v0`
- `composelens.check.v0`
- `composelens.fixtax.v0` (internal fixture harness JSON; not a CLI report)
- `composelens.engineadapter.v0` (internal engine capture JSON; not a CLI report; not a differential)
- `composelens.enginecap.v0` (capability map nested on doctor as `engineCapabilities`)
- `composelens.differential.v0` (internal vs live `docker compose config`; not a claim of engine parity)
- `composelens.reproduce.v0` (generated `docker compose … config` command; files/flags only)
- `composelens.policy.v0` (external check policy overlay; invalid files fail before analysis)
- `composelens.unsupported.v0`
- `composelens.report.v0` (self-contained JSON data package from `report --json`; not HTML)
- `composelens.error.v0` (stderr JSON on command failure: `message`, `code`, `remediation`, `doc`)

Unknown future commands use `composelens.unsupported.v0` rather than a fake success document.
