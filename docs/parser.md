# Parser and loader hardening

ComposeLens treats Compose YAML/JSON as **untrusted data**. The parser and file loader apply fixed resource bounds and return a **typed, secret-safe diagnostic** instead of panicking, hanging, or exhausting memory.

This does **not** change interpolation, merge, profiles, include, extends, container-environment, normalization, or differential logic. Those stages consume a successfully parsed document.

## Bounds (defaults)

See `docs/limits.md` for the shared invocation budget (aggregate bytes, file count, engine output). YAML walk caps stay here:

| Bound | Value | Rationale |
| --- | --- | --- |
| Per-file size | 1 MiB | Ordinary Compose files are kilobytes; Stat-before-read refuses oversized files before they are fully processed. |
| Total untrusted input | 4 MiB | Shared across discovered Compose files, transitive `include:` / `extends:` loads, env files, policy, and engine stdout/stderr. |
| Unique files | 256 | Caps many-small-file lists and include/extends fan-out. |
| Engine stdout/stderr | 4 MiB per stream | Bounded read of `docker compose config` (and version) capture; also charged against the 4 MiB aggregate. |
| YAML nesting (mapping + sequence) | 64 | Compose models are shallow; yaml.v3’s own cap is 10000. |
| Alias expansion visits | 4096 | Defeats alias-bomb / “billion laughs” graphs. Alias cycles are refused. |
| YAML node count | 50 000 | Step-bound on the node walk. |
| Parse timeout | 2s | Wall-clock backup if unmarshal/walk of a bounded file still runs too long. |

Exceeding a bound returns `internal/safety.ParseError` with a stable `Code` (for example `yaml-too-deep`, `yaml-alias-limit`, `input-too-large`, `input-total-too-large`, `input-too-many-files`, `engine-output-too-large`, `include-expansion-limit`, `invalid-encoding`, `yaml-malformed`, `duplicate-mapping-key`, `yaml-not-mapping`, `parse-timeout`; for env files `env-syntax` and `env-unsupported`). Diagnostics do **not** echo YAML snippets or secret-shaped values. CLI `inspect` / other project commands still use exit **3** (`Input`) for these failures (`docs/cli.md`). The same holds for a file reached through `include:` or `extends:`: a refused included or extended file fails the whole run with its typed code; it is never reported as a nested error state with a clean result. An absent included file, an include cycle, include depth and unsupported forms remain typed states (`docs/include.md`, `docs/extends.md`).

## Valid files

Ordinary Compose (and valid files nested under the depth bound) still parse. A file that holds several YAML documents (separated by `---`) is read as Compose reads it: each later document is merged over the earlier ones, as if it were a further `-f` file. An empty trailing document is ignored. A valid file’s acceptance can be compared to live `docker compose config`; the engine does not define ComposeLens’s resource bound for hostile input.

## Include / extends loads

`include` / `extends` disk loads use the same per-file 1 MiB bound and the shared invocation budget (`docs/limits.md`). A tree of individually legal files that sums past 4 MiB (or 256 unique paths) fails typed before analysis.
