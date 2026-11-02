# Top-level `include:`

ComposeLens resolves Compose **`include:`** after per-file interpolation and **before** extends, multi-file merge, and profile activation. Included files are the **base**; the including file's own mappings **override** that base. This is not container-environment precedence or a provenance graph.

## Order of operations

1. Discover Compose files.
2. Interpolate string scalars in each file, including `include:` paths.
3. **Expand `include:`**: load each included path relative to the including file, recurse nested includes, then treat the including file (minus the `include:` key) as the last overlay.
4. Resolve service `extends` on each overlay file.
5. Merge the expanded document list.
6. Activate service profiles on the merged model.
7. Resolve the container environment.

## Forms

| Form | Example | Behavior |
| --- | --- | --- |
| Short list | `include: [a.yaml, b.yaml]` | Load in list order. |
| Long list of mappings | `include: [{path: a.yaml}, {path: b.yaml}]` | Load each `path` in order. |
| Scalar (not a list) | `include: commons.yaml` | Compose rejects the file (``include` must be a list``). ComposeLens applies it as a one-item list so the model stays readable, marks the include and every value it brings `unknown` with that reason, and `check` reports the error. |
| Mapping (not a list) | `include: {path: commons.yaml}` | Same as the scalar form: Compose rejects it; applied as a one-item list, `unknown`, reported by `check`. |

An included file that holds several YAML documents is applied with its first document only and marked `unknown` with that reason (Compose merges them all). Root files (`-f`, the default file) merge every document, as Compose does (`docs/parser.md`).

Paths resolve **relative to the including file's directory**, not the process working directory (unless they are already absolute).

## Long-form extras (not guessed)

Compose documents `project_directory` and `env_file` on long-form include entries. ComposeLens **loads `path`** and records those extra keys as `unknown` / not applied. It does not change the project directory or merge extra env files for an include. Engine-parity for those fields is unverified.

## Nesting, cycles, depth

Nested `include:` is resolved recursively. A cycle (`A` includes `B` includes `A`) is a typed `cycle` state: the looping edge is **not** followed, so inspect cannot hang. Nesting deeper than 16 is a typed `depth` state. A missing included file is `absent`. An included file that the parser or a safety bound refuses (malformed YAML, invalid UTF-8, a duplicate key, nesting or size limits) fails the run with exit 3 and its typed code, like a refused root file (`docs/parser.md`). Included files share the invocation input budget (`docs/limits.md`).

## Precedence

Multiple `include:` entries are processed **in order**. Later included files overlay earlier ones (merge rules). The including file then overlays that combined base. Where an edge case is not clearly documented versus the official engine, inspect marks `unknown`/`unsupported` instead of guessing.

## Surface

`composelens inspect` keeps `view: source-level`, interpolation, merge, profiles, and extends sections, and adds `includes` / `includesDisclaimer` (the include graph) plus per-field `includeChain` on merge rows when the winning file was pulled in through includes. Secret values inside included files are redacted through `internal/redact`.

## Not implemented

Applying include `env_file` / `project_directory`, provenance graph, engine differential.
