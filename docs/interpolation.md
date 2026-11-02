# Interpolation

ComposeLens resolves Compose **interpolation** expressions against interpolation sources. Multi-file merge is a later stage (`docs/merge.md`). This is not container `environment`/`env_file` precedence and not a provenance graph.

## Grammar

| Form | Meaning |
| --- | --- |
| `$VAR` / `${VAR}` | Substitute the value; unset or empty → empty (`absent-empty`) |
| `${VAR:-default}` | `default` when unset **or** empty |
| `${VAR-default}` | `default` when **unset** (empty is kept) |
| `${VAR:?err}` | Typed `required-error` when unset or empty; no fabricated value |
| `${VAR?err}` | Typed `required-error` when unset |
| `${VAR:+replacement}` | `replacement` when set and non-empty |
| `${VAR+replacement}` | `replacement` when set (including empty) |
| `$$` | Literal `$` (`escaped-literal`) |

**Nested text.** Default and replacement text is interpolated as Compose interpolates it: `${MISSING:-$OTHER}` expands `OTHER`, `${A:-${B:-c}}` nests (braces are matched, so `${UNSET:-a}b}` is `ab}`), and `$$` inside the text is a literal `$`. Nesting deeper than 8 levels is kept as written with certainty `unknown`; `differential` classifies that row as the known limitation D4 (`docs/differential.md`).

**Values in `.env` and `--env-file`.** Unquoted and double-quoted values are interpolated as Compose does: a reference looks up the process environment first, then the earlier entries of the same and earlier env files (`B=bee` then `EXP=${B}-x` gives `bee-x`; a forward reference is empty), and `$$` becomes `$`. Single-quoted values are literal.

**Forms Compose rejects.** `${}`, `${1A}`, an unclosed `${A` and operators other than `:-`, `-`, `:?`, `?`, `:+`, `+` (for example `${A:0:2}`) make Compose refuse the whole file. ComposeLens keeps the raw text, reports state `invalid-format` with certainty `unknown`, and `check` reports the error (`docs/check.md`). A `$` not followed by a name or `{` (`$@`, a trailing `$`) stays literal, as in Compose.

## Precedence (interpolation stage only)

**host shell (full process environment, name lookup only) > `--env-file` / `COMPOSE_ENV_FILES` (later overlay wins).** Explicit `--env-file` **replaces** `COMPOSE_ENV_FILES` (a missing predefined path is not an error when `--env-file` is given). `COMPOSE_ENV_FILES` is a **comma-separated** list on every platform. The selected `--env-file` / `COMPOSE_ENV_FILES` set **replaces** the project `.env` (matching Docker Compose). Project `.env` is loaded only when that set is empty.

The `.env`, `--env-file` and `COMPOSE_ENV_FILES` files are read with the same env-file grammar as service `env_file:` (quoting, escapes, multiline values, `KEY: value`, refusals with exit 3; `docs/containerenv.md`).

Inspect `unappliedSources` lists the project `.env` only when that file exists and is **not** in the selected interpolation set (`applied: false`, stage `project-env`). That is distinct from an explicitly selected project `.env` (`--env-file .env`), which is read as stage `env-file` and is not listed as unapplied.

Inspect’s source-level environment listing remains the host **allowlist**. Interpolation may consult a name from the full shell without dumping the entire environment.

## Surface

`composelens inspect` keeps `view: source-level` and adds `interpolation` / `interpolationDisclaimer`. Official Compose fails the project on required-unset; ComposeLens **reports** `required-error` instead of inventing a value. Merge interpolates a clone of each file first, then overlays; the interpolation section still shows the original expressions.

Interpolated secrets (by variable name or resolved content) are redacted through `internal/redact`. Interpolation **syntax** (`${VAR:-default}`) is not classified as a secret by length or entropy. Bare `$VAR` is unchanged for that classifier. When interpolation is secret-designated (secret key, known secret pattern, or secret resolved value), inspect withholds the raw expression — including a default that has no vendor-token prefix. Known secret patterns in the expression and secret resolved values still redact; an unredacted secret still fail-closes.
