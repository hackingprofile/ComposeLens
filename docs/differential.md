# Engine differential

`composelens differential` compares ComposeLens's **internal effective model** to a live `docker compose config` captured through the engine adapter (`docs/engineadapter.md`).

This is a **truth-finding** command. Divergences are success (honest findings), not a product failure. It does **not** change interpolation, merge, profiles, include, extends, container-environment, or normalization to manufacture agreement — except that `docker compose config` dump-escaping (`$$` printed for a runtime `$`) is de-escaped **once** on the engine side so escaped literals compare as runtime values (`$VAR` == `$VAR`).

## Comparison

Both sides are canonicalized with the dual-form model (`docs/normalize.md`) before ports/volumes/labels/command/entrypoint/healthcheck.test are compared. Cosmetic short↔long form is not reported as a divergence. If either side's canonical form is `unknown`, the row is `uncertain` — never silent agreement.

Other compared leaves: service presence (enabled vs engine config), scalar and nested-map service fields such as `image` and engine-injected `networks`, and container-environment variables. Nested map keys are grouped at the first field (`services.web.networks.default` → `services.web.networks`) so engine-only mappings are not omitted.

Row states: `match` / `divergent` / `only-internal` / `only-engine` / `uncertain`.

A `divergent` or engine-injected `only-engine` row may carry `classification` + `detail` so it is **explained**, not a silent mismatch:

| ID | Classification | Meaning |
| --- | --- | --- |
| D1 | `by-design` | Bind volume `source` stays as written in ComposeLens (portable, deterministic). The engine resolves a host-absolute path. ComposeLens does **not** emit machine-specific paths to chase parity. |
| D2 | `by-design` | Shell-string `command`/`entrypoint` stay shell form. Compose spec treats string vs list as different (shell vs exec). `docker compose config` dumps shell form as exec argv. Matching that dump would mislabel shell form as exec. |
| D3 | `by-design` | ComposeLens models source-declared configuration and does **not** synthesize the engine's implicit default network. `docker compose config` injects `networks.default` (often `default: null` on the service). That `only-engine` (or extra-`default`) row is explained; custom networks and unrelated fields stay unlabeled. |
| D4 | `known-limitation` | Default text nested more than 8 levels deep (`${A:-${B:-…}}`) is kept as written with certainty `unknown`; the engine expands it. Nesting up to that depth is interpolated exactly. |

Unrelated value disagreements stay `divergent` / `only-engine` / `only-internal` with empty `classification` (unexplained until investigated). ComposeLens does not invent networks to chase parity.

## Secrets

When both raw values exist, the comparator fingerprints them in-process (SHA-256 over the UTF-8 bytes of each side) and sets `state: match` or `state: divergent` with `certainty: proven`. Display stays `[redacted]`. The fingerprint is never written to stdout, stderr, JSON, SARIF, or test evidence.

If a side is already a withheld placeholder (`[redacted]`), the row is `state: uncertain` with `certainty: unknown` — never a proven match or divergence from comparing placeholders. Only-internal / only-engine secret rows stay presence facts (`values not shown`).

The CLI captures engine config through the adapter, which withholds secrets before parse. That path therefore reports typed uncertainty for secret env rows. Value-dependent match/divergent is proven by feeding both raw values to the comparator (unit tests and live unredacted `docker compose config`).

## Engine absent

If Docker is missing, the report has `engineState: engine-absent` and **no fabricated rows**.

JSON schema: `composelens.differential.v0`.
