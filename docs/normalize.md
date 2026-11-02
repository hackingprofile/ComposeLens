# Normalization

ComposeLens canonicalizes **documented dual-form Compose fields** on the already-merged model so equivalent short and long forms **compare equal**. This is not a new resolver. Interpolation, include, extends, merge, profiles, and container-environment semantics are unchanged.

`environment:` / `env_file:` list-vs-map remain owned by container-environment precedence (`docs/containerenv.md`). They are not re-derived here.

## Fields

| Field | Equivalent pair | Distinct pair | Basis |
| --- | --- | --- | --- |
| `ports` | short `"8000:8000"`, `"8000"`, `"127.0.0.1:8000:8000/tcp"` ⇄ long `{target, published, host_ip, protocol, mode}` | different published/target/host_ip/protocol/mode | Compose Specification ports short vs long syntax. Default protocol `tcp`, default mode `ingress`. |
| `volumes` | short `./src:/dst:ro` ⇄ long `{type: bind, source, target, read_only}` (and named volume ⇄ `{type: volume, …}`). Short syntax is parsed by `internal/shortvol` (Windows `C:\path` is the source, not a colon split). **D1 (by-design):** relative bind `source` stays as written. The engine's `docker compose config` dump often absolutizes the host path. ComposeLens does not emit that machine-specific path (`docs/differential.md`). | read-only vs read-write; bind vs named volume; extras that have no lossless pair | Compose Specification volumes short vs long syntax. Type omitted on long form is inferred from the source (certainty `inferred`). |
| `labels` | list `["k=v"]` ⇄ map `{k: v}` | different key or value | Compose Specification labels. Order-insensitive map. List item without `=` is key with empty value. |
| `command` / `entrypoint` | flow sequence ⇄ block sequence with the **same argv** (both exec) | **string (shell) vs list (exec)** — **D2 (by-design):** ComposeLens keeps that distinction. The engine dump may serialize a shell string as exec argv; `differential` labels that explained, not a silent mismatch (`docs/differential.md`). | Compose Specification: string is shell form, list is exec form. They are **not** semantically identical. Representation is canonicalized; shell vs exec stay distinct. |
| `healthcheck.test` | string `"curl -f localhost"` ⇄ `["CMD-SHELL", "curl -f localhost"]` | that string vs `["CMD", "curl", "-f", "localhost"]` | Compose Specification: a string is equivalent to specifying `CMD-SHELL` followed by that string. `CMD` is exec. `["NONE"]` disables. |

## Uncertainty

Where a conversion is not documented as lossless (extra long-form keys, unparseable short syntax, consistency-mode volume tokens, empty-list vs string `[]` for command), the item is `unknown` / `unsupported`. Unknown items do **not** compare equal to a parsed form.

IPv6 host bindings that do not match `[addr]:published:target` / `[addr]:target` are unknown rather than guessed. Port ranges that parse as `published`/`target` strings (for example `8000-8001:80`) stay as those strings.

## Provenance and secrets

Each canonical item keeps the merge-stage winning file and line. Secrets are classified with `internal/redact` and redacted on `inspect` / `diff` output. Fail-closed still applies.

## Surfaces

- **inspect** (additive): `normalizationDisclaimer` + `normalization`. Inspect remains `view: source-level`.
- **diff** (minimal wiring): dual-form families are compared as canonical values instead of raw merge-path strings, so equivalent short/long forms do not emit cosmetic field changes. Non-equivalent forms still `changed`. `diff` is still not an engine differential.
- **explain**, **explain --all**, **check**: unchanged in meaning; they keep working on the same stage outputs.

## Out of scope

Docker engine adapter / `docker compose config` differential, HTML report, policy engine, SARIF upload, new interpolation/merge/profile/include/extends/container-env rules.
