# Service `extends`

ComposeLens resolves Compose **`extends`** after per-file interpolation (and after that file has been produced by include expansion) and **before** multi-file merge and profile activation. The referenced service is the starting config; the extending service's own keys apply on top. This is not container-environment precedence or a provenance graph.

## Order of operations

1. Discover Compose files.
2. Interpolate string scalars, including `include:` paths.
3. Expand `include:`.
4. **Resolve `extends`** on each overlay file's services.
5. Merge the expanded+resolved documents.
6. Activate service profiles.
7. Resolve the container environment.

A base service that only exists because of `include:` (no explicit `extends.file`) is looked up in the current file only and is `absent` if missing. That include interaction is not fully modeled.

## Forms

| Form | Example | Behavior |
| --- | --- | --- |
| Mapping | `extends: {service: common}` | Same-file inheritance. |
| Mapping + file | `extends: {file: base.yaml, service: web}` | Load `file` relative to the **extending** file, then take `service`. |
| String | `extends: common` | **Unsupported** — the Compose Specification requires a mapping. Local keys are kept; nothing is inherited. |

## Merge rules (documented `extends`, not multi-file overlay)

| Kind | Rule |
| --- | --- |
| Scalar | Child wins. |
| Mapping | Deep-merge (`environment`, `labels`, `healthcheck`, …). |
| Documented sequences (`ports`, `expose`, `cap_add`, …) | Concatenate (base first, child after) and drop duplicate items. |
| `volumes` / `devices` | Unique by container target via the shared `internal/shortvol` parser (Windows drive-letter sources included); otherwise unique by rendered item. |
| Other sequences (`command`, `entrypoint`, …) | Child **replaces** (not concatenated). Engine-parity for concat vs replace is `unknown`. |

## Keys that are not inherited

Copied from the Compose Specification's relationship-key restrictions (not blindly merged from the base):

`depends_on`, `links`, `volumes_from`, `container_name`, `ipc`, `pid`, `network_mode`, `net`, and `extends` itself (the child's `extends` is used to find the base, then stripped).

The child may still set those keys locally.

## Nesting, cycles, depth

Nested `extends` is resolved recursively. A cycle is a typed `cycle` state: the looping edge is not followed, so inspect cannot hang. Depth greater than 16 is `depth`. A missing file or service is `absent`. Cross-file `extends` loads share the invocation input budget (`docs/limits.md`).

## Surface

`composelens inspect` keeps source-level, interpolation, include, merge, and profiles views, and adds `extends` / `extendsDisclaimer` plus per-field `extendsOrigin` / `extendsChain` on merge rows. Secrets inside an extended base service are redacted through `internal/redact`.

An inherited value keeps the file and line where it is written. When `c` in `compose.yaml` extends `base` in `sub/base.yaml`, a key `c` inherits is reported at `sub/base.yaml:line:column` in the merge and container-environment stages, `explain`, `check` SARIF `physicalLocation` and `--github` annotations; through a nested chain (`compose.yaml` → `sub/mid.yaml` → `deep/root.yaml`) each value names the file that holds it. Keys the extending service sets itself name the extending file.

## Not implemented

Provenance graph, applying string short-form `extends`, inheriting relationship keys, engine differential.
