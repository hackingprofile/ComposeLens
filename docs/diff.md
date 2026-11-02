# Diff

`composelens diff` answers: **what effective values differ between two selections over the same Compose files, and which source produced each side?**

It is a **comparison/presentation** surface. Both sides run the existing interpolation → include → extends → merge → profiles → container-environment pipeline. `diff` does not re-derive those stages. It is **not** a provenance graph and **not** an engine differential against `docker compose`.

`inspect` and `explain` stay unchanged **in meaning** (inspect remains source-level; an additive `normalization` section is present). Diff is additive.

## Flag surface (same files, two selections)

| Flag | Meaning |
| --- | --- |
| `--left-profile <name>` | Repeatable. Left active profiles. If any are given, they are the left set (override `--profile` / `COMPOSE_PROFILES` on the left). |
| `--right-profile <name>` | Repeatable. Right active profiles. If omitted, the right set copies the left set. |
| `--left-env-file <path>` | Repeatable. Left interpolation env-files (**replace** project `.env` on that side). If any are given, they replace `--env-file` on the left. |
| `--right-env-file <path>` | Repeatable. Right interpolation env-files. If omitted, the right list copies the left list. |

`--file` / `--project-directory` are shared. Comparing two entirely different file sets is deferred.

No left/right selectors means both sides use the same `--profile` / `--env-file` (and `COMPOSE_PROFILES`). Identical sides produce an **empty** diff.

## What is compared

Per target, in deterministic order:

- **services** newly enabled or disabled (`added` / `removed`)
- **fields** of enabled services (except `environment` / `env_file` / `profiles` / `extends`, which are represented by other stages). Dual-form families (`ports`, `volumes`, `labels`, `command`, `entrypoint`, `healthcheck.test`) compare as **canonical** values so equivalent short/long forms do not emit cosmetic changes (`docs/normalize.md`).
- **container-environment variables** of enabled services (`added` / `removed` / `changed`)

A **changed** target reports the left and right values and the **winning source on each side** (drawn from existing stage / `explain` provenance). Two identical effective models yield `changes: []` / `empty: true`. Dual-form short vs long that canonicalize equal also yield no field change for that family.

## JSON

Schema: `composelens.diff.v0`.

Stable keys: `schema`, `product`, `version`, `disclaimer`, `left`, `right`, `changes`, `empty`, `evidence`, `certainty`.

`inspect` and `explain` JSON do not gain diff fields.

## Secrets

A secret that differs is **changed by presence**. Both values are redacted. Fail-closed output guard still applies. Synthetic secret probes run in-process and are not stored with test evidence. Engine differential secret rows (`composelens differential`) are typed uncertainty, because the engine capture withholds secrets before the comparison (`docs/differential.md`); this command is not that surface.

## Not this command

- Different Compose file sets
- Policy engine / custom rules
- Provenance graph / shadow chains
- Engine differential (`docker compose config` parity)
- HTML / SARIF **upload**
- Changing interpolation through explain resolution behavior (diff wiring for canonical dual-form compare is recorded in `docs/normalize.md`)

`check` is a separate command (`docs/check.md`). Local SARIF is an output of `check`, not of `diff`.
