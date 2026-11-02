# Container environment

ComposeLens computes the **container environment** from each service's `environment:` and `env_file:` after interpolation, include expansion, extends, merge, and profile activation. This is a **different stage** from interpolation, which only substitutes `${VAR}` in Compose YAML text.

Escaped Compose literals (`$$VAR`, `$${NAME}`, `pre-$$HOME-post`) keep the interpolation stage's `escaped-literal` result (`$VAR`, `${NAME}`, `pre-$HOME-post`) in the effective environment. They are not passed through the host shell and not interpolated a second time. Unset `$UNDEFINED` / `${UNDEFINED}` still become empty, matching the engine.

It is not Dockerfile `ENV`, not `docker compose run -e`, and not a provenance graph.

## Order of operations

1. Discover Compose files.
2. Interpolate Compose-model strings.
3. Expand `include:`.
4. Resolve `extends`.
5. Merge files.
6. Activate profiles.
7. **Resolve the container environment**.

## Documented precedence (in scope)

Lowest to highest:

| Source | Rule |
| --- | --- |
| `env_file:` | Single path or list. Paths resolve relative to the Compose file that declared them. Later files override earlier files for the same key. |
| `environment:` | Map form (`KEY: value`) and list form (`KEY=value`). **Always overrides `env_file`**, including empty values. |

List-form `- KEY` (no value) **passes through from the host shell**. If `KEY` is not in the process environment, the variable is **unset and removed** (even if an `env_file` had set it). Map-form `KEY:` (a YAML null, also `KEY: ~`) passes through from the host the same way. Map-form `KEY: ""` (a quoted empty string) sets the variable to the empty string, as Compose does.

Names under `environment:` are `[A-Za-z_][A-Za-z0-9_]*` (no `.`), so they cannot collide with the `services.<svc>.environment.<KEY>` path vocabulary. Names read from an `env_file:` follow the engine instead: letters, digits and `_ . - [ ]` (for example `FOO.BAR`, `A[0]`) are kept exactly as written; any other character refuses the file (exit 3, `env-syntax`).

Project `.env` and CLI `--env-file` feed **interpolation**. CLI `--env-file` / `COMPOSE_ENV_FILES` **replaces** the project `.env` for that interpolation table; they are **not** injected into the container unless the service names them via `environment:` / `env_file:`.

## `env_file` format

One env grammar (`internal/envfile`) reads the project `.env`, CLI `--env-file` / `COMPOSE_ENV_FILES` and service `env_file:`, and it was checked against `docker compose config` (Compose v5.4.0):

- blank lines and `#` comment lines are skipped; an optional `export ` prefix; `KEY=value` or `KEY: value`; `KEY` alone (no value) is inherited from the host shell;
- unquoted values end at the line end; ` #` starts a comment; surrounding white space is trimmed; backslashes stay literal;
- single- and double-quoted values may span lines; inside both, `\` before the quote character yields the quote and `\` before any other character is kept with it; a double-quoted value then expands `\a \b \f \n \r \t \v \\ \" \$ \uXXXX \0NNN`; text after a closing quote is read as the next entry;
- the file must be valid UTF-8 (otherwise `invalid-encoding`); an unterminated quote or an invalid name is `env-syntax`; an empty name is `env-unsupported`. Each refuses the run with exit 3 and empty stdout, as the engine refuses it;
- `format: raw`: each line is `KEY=VALUE` with the value kept byte for byte (quotes, `$` and spaces included), without interpolation.

Unquoted and double-quoted values in a service `env_file:` are interpolated as Compose does: a reference looks up the project environment (process environment, then `.env` / `--env-file`) first, then the earlier entries of the same file; `$$` becomes `$`. Single-quoted values are literal. Values in `.env` / `--env-file` are interpolated the same way when they are read (`docs/interpolation.md`). A mixed list of short (`- a.env`) and long (`- path: b.env`) entries is one ordered list. Long-form `required: false` ignores a missing file. Other `format` values are recorded `unknown` and still parsed as Compose env_file rules.

Service `env_file:` paths are untrusted input: each file is bounded at 1 MiB and charged against the shared invocation budget (`docs/limits.md`). Over-cap fails typed before analysis.

## Not applied

| Source | Handling |
| --- | --- |
| Image `ENV` / Dockerfile | `unknown` / `unsupported` — no image is built or read; no fabricated variables |
| `docker compose run -e` / `--env` | Out of scope |
| Include long-form `env_file` | Still not applied |

## Surface

`composelens inspect` keeps source-level, interpolation, include, extends, merge, and profiles views, and adds `containerEnvironment` / `containerEnvironmentDisclaimer`. Each variable shows the winning source (`environment` / `env-file` path / `host-shell`) and ordered losers. Secrets are redacted through `internal/redact`.
