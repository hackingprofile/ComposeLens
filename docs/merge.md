# Multi-file merge

ComposeLens merges **already interpolated** per-file models in Compose file order after **include expansion** (`docs/include.md`) and **extends resolution** (`docs/extends.md`). Trees that extends has already substituted are not interpolated again (a second pass would expand escaped `$VAR` as a real variable). Service profiles are a later stage (`docs/profiles.md`). This is not container-environment precedence or a provenance graph.

## Order of operations

1. Parse each Compose file.
2. Interpolate string scalars in that file.
3. Expand top-level `include:`; included models are the base, the including file overrides.
4. Resolve service `extends` on each overlay file.
5. Overlay the interpolated models **in expanded file order** (`-f` / `COMPOSE_FILE` / default discovery, with includes inserted before each including file).
6. Activate service profiles.
7. Resolve the container environment.

Interpolation semantics are not reopened here. Required-unset interpolation still becomes an empty string in the merged tree (inspect’s interpolation view reports `required-error` on the original expression).

## Rules implemented

| Kind | Rule | Certainty |
| --- | --- | --- |
| Scalar | Later file overrides earlier. Earlier-only scalars are kept. | `proven` |
| Mapping | Deep-merge: later overrides matching keys, adds new keys, keeps earlier-only keys. | `proven` |
| Sequence (general) | Later items **append** to the earlier list (`dns`, `dns_search`, `expose`, `cap_add`, `cap_drop`, `tmpfs`, `extra_hosts`, `security_opt`, live-checked). Other sequences append with certainty `unknown` until live-checked. | `proven` or `unknown` |
| Unique-resource sequences | Append with de-duplication by unique key. Later item wins on the same key. `ports` `{ip, target, published, protocol}` (protocol defaults to `tcp`); `volumes` by **container target** (short syntax parsed by the shared drive-aware `internal/shortvol` parser so `C:\Alpha:/data` keys as `/data`, not `\Alpha`); `secrets`/`configs` by source/name; `environment` list items by variable name; `depends_on` list items by service name. | `proven` (live-checked) |
| Atomic sequences | Later list **replaces** the earlier: `command`, `entrypoint`, `healthcheck.test`. | `proven` (live-checked) |
| `!reset` | Resets that node; children are dropped. **Available** in `gopkg.in/yaml.v3` (tag preserved). | `proven` |
| `!override` | Replaces a mapping instead of deep-merging. **Available** in yaml.v3. | `proven` |

Per-field report: winning file + value, overridden contributors in overlay order, action (`source` / `add` / `override` / `replace` / `append` / `reset`). Certainty is `proven` when the rule was live-checked against `docker compose config`; otherwise `unknown` — never a false `proven`.

Documented `extends` sequence concatenation is a separate stage (`docs/extends.md`).

## Surface

`composelens inspect` keeps `view: source-level` and the interpolation and include sections. It adds `merge` / `mergeDisclaimer`. Secret values (by key name or content, including overridden contributors and appended list items) are redacted through `internal/redact`. Merge rows may carry `includeChain` when the winning file arrived through `include:`.
