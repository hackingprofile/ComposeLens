# Provenance graph

`composelens explain --all` answers: **for every effective service, field, and container-environment variable in this model, which existing stages produced it, and which contributors won or were shadowed?**

It is a **read-only aggregation**. It does not re-derive interpolation, include, extends, merge, profiles, or container-environment semantics. Graph assembly keeps the entity it is emitting (service, field, or `service:VAR`) and does not reparse that identity as a colliding textual target. Single-target `explain <target>` still refuses a string that matches more than one entity. Graph node `target` strings may therefore repeat when `kind` differs; uniqueness is `(kind, target)`. Report HTML selection uses that pair. Graph node targets use the same reversible service identity as `explain` (`web.api` is not truncated to `web`; a service named `web.image` does not consume `web`'s image field).

Single-target `explain <target>` is unchanged (`docs/explain.md`). `inspect`, `diff`, and `check` are unchanged.

## Surface

| Invocation | Result |
| --- | --- |
| `explain --all` | Whole-model graph (human summary) |
| `explain --all --json` | `composelens.graph.v0` |
| `explain <target>` | Unchanged single-target account (`composelens.explain.v0`) |
| `explain` with neither target nor `--all` | Usage, exit 2 |
| `explain --all <target>` | Usage, exit 2 |
| `--all` on any other command | Usage, exit 2 |

`--sarif` and `--github` remain `check` only.

## Nodes

Every **effective** service, merge field of an enabled service (except `environment` / `env_file` / `profiles` / `extends`, which are represented as env or service nodes), and container-environment variable of an enabled service is a node. Disabled services appear as service nodes with the profiles stage only — the same as `explain web` on a disabled service.

A name that is not in the model is **not** emitted. `Lookup` of a missing target is typed `absent` with an empty chain. Nothing is fabricated.

## Shadow-chains

Each node carries an ordered `shadowChain`: losers first, winner last, **per stage that actually applied**. Stages that do not apply are omitted.

An extends link names a file only when that file's original service actually sets the field. Intermediate files that merely inherit it remain in the extends traversal information, but are not listed as shadowed value sources.

| Stage | Links |
| --- | --- |
| interpolation | Project `.env` → `--env-file` (collection order) → host-shell when those `envsrc` bindings exist for the interpolated key. The interpolation winner is marked from the existing interp source. If bindings are absent, only the interpolation winner from `explain` is emitted — `.env` / shell losers are not invented. |
| include | Include chain of the winning file when longer than one hop |
| extends | Base then local origin (`inherited` / `override` / `concat`) |
| merge | Overridden contributors, then the winning file |
| profiles | Enabled or disabled, with the typed state |
| container-environment | Ordered `env_file` / host-shell losers, then the `environment:` (or other) winner |

Typed states are reused from interpolation through container-environment. Uncertain linkages are `unknown` / `unsupported`, never guessed.

## JSON

Schema: `composelens.graph.v0`.

Stable keys: `schema`, `product`, `version`, `disclaimer`, `nodes`, `counts`, `evidence`, `certainty`.

Each node: `target`, `kind`, `state`, `effective` (omitted when secret), `secret`, `finalStage`, `reason`, `shadowChain`, `certainty`, `evidence`. Nodes are unique by `(kind, target)`, not by `target` alone. Kinds are `service`, `field`, `env` and `include`. An `include` node is an include reference that did not load (`absent`, `cycle`, `depth`, or `unsupported`, for example a remote include); its target is the resolved path (or the reference as written) and its chain names the including file. Loaded includes appear in field chains.

Each shadow-chain link: `order`, `role` (`winner` \| `shadowed`), `stage`, `kind`, `source`, `state`, `secret`, `certainty`, `evidence`.

`disclaimer` is:

`whole-model provenance graph assembled from existing stage outputs — not a new resolver, not an engine differential`

Inspect JSON (`composelens.inspect.v0`) and single-target explain JSON (`composelens.explain.v0`) do not gain graph fields.

## Secrets

Secret values are withheld. Human output also runs secret-shaped strings (including high-entropy paths) through `internal/redact` → `[redacted]`, so fail-closed is not the only safety net. JSON may still contain escaped paths that the classifier treats as secrets. Synthetic probes run in-process and are not stored with test evidence.

## Not this command

- A new resolver or engine differential
- Policy engine / custom rules, HTML report, SARIF for the graph
- Recursive interpolation
- Changing interpolation through differential resolution, single-target explain, inspect, diff, or check behavior
