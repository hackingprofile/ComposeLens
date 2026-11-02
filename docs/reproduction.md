# Reproduction command

`composelens reproduce` prints the exact, minimal, deterministic **`docker compose … config`** invocation that recreates ComposeLens's modeled configuration for the same analysis inputs.

It is **not** a differential and does **not** run Docker. That running the command matches the model is checked by the live test `TestLiveReproductionMatchesModel`.

## What is emitted

From `--project-directory`, the ordered discovered/`-f` files, the selected env-file set (explicit `--env-file`, or `COMPOSE_ENV_FILES` when no `--env-file` is given), and `--profile` / `COMPOSE_PROFILES`:

```
docker compose --project-directory <dir> -f <file> … --env-file <file> … --profile <name> … config
```

- Flag order matches the engine adapter (`docs/engineadapter.md`).
- The human `command` line is **POSIX single-quote-safe** for copy-paste into `sh`/`bash`/`zsh`. Conservative tokens (`[A-Za-z0-9_@%+=:,./-]`) stay bare; every other token is single-quoted, with embedded `'` as `'\''`. Shell metacharacters (`$()`, backticks, `;`, `|`, `&`, redirects, globs, spaces) are literal. The copy-paste line is not a `cmd.exe` / PowerShell form; **`argv` is the canonical cross-shell token list** and is what live validation executes.
- Project `.env` is **not** passed as `--env-file`. When the generated command has no `--env-file`, Compose (and ComposeLens) load `.env` from the project directory. When `--env-file` / `COMPOSE_ENV_FILES` is present, that set **replaces** `.env`.
- Secret values are never inlined. Secret-shaped profile names fail closed (exit 4).

## Live match

For the labs in `examples/reproduce-lab/` (multi-file merge, profile-gated, env-file), the live test executes the generated command with the installed Docker Compose version and records that version. Parsed `config` is compared to ComposeLens's model with the canonical compare (`docs/differential.md`), using the same in-scope fields as the live corpus MATCH assertion (`image` / `hostname` / dual-form families / container-env). Default engine-injected `networks` stay out of that MATCH scope.

## JSON

Schema `composelens.reproduce.v0`. See `docs/cli.md`.
