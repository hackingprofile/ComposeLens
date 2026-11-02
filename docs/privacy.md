# Privacy

ComposeLens is **local-first** and **secret-safe by default**.

## Local-first

- ComposeLens reads the files you name (or the defaults in the project directory), a **small allowlist** of host environment variables, and the variables your Compose files reference by name.
- It does not phone home, create accounts, or send Compose files to a model provider. It never starts or runs containers, never pulls images, and never transmits your project to Docker Hub. Internal failures print crash guidance that nothing is sent anywhere. `doctor --bundle` writes local diagnostic metadata only (`docs/support.md`).
- Optional Docker CLI subprocesses are local:
  - **`doctor`** invokes `docker compose version` (detection). It does not pass the project selection to Docker.
  - **`differential`** invokes `docker compose config` **with your project selection** (`--project-directory`, `-f`/`--file`, `--env-file`, `--profile`) to compare ComposeLens's model against the engine's resolved config. That command is **client-side** local resolution: it does not require the daemon.
  - **`report --json` / `report --html`** run the same `docker compose config` capture with the same selection to fill the report's differential section (`docs/report.md`). Engine-absent yields a typed empty section.
  - **`reproduce`** prints a `docker compose config` command with the same selection flags; it does **not** execute it.
- Network boundary: ComposeLens itself makes no network calls, and local `docker compose config` needs none for a local project. A remote include (`oci://`, Git or `http(s)://` under `include:`) would make the engine resolve it over the network, so `report` and `differential` skip the capture (engine state `skipped`, reason recorded) unless `--allow-network` is given. ComposeLens does not load remote includes itself; they appear in `inspect` as `unsupported` with that reason. `report --no-engine` runs no Docker command.

## What is collected

| Source | When | Tagged as |
| --- | --- | --- |
| Compose files | defaults, `--file`/`-f`, or `COMPOSE_FILE` | file origin + digest |
| Project `.env` | when it is the selected interpolation set (no `--env-file` / empty `COMPOSE_ENV_FILES`) | stage `project-env`, path + line |
| `--env-file` | each flag, in order (including an explicit project `.env`) | stage `env-file`, path + line |
| Unselected project `.env` | file exists but a replacement set is selected | inspect `unappliedSources` (`applied: false`); the file is not read |
| Host shell | **allowlist only** (below) | stage `host-shell` |

ComposeLens does **not** dump the host environment. Special files such as `/proc/self/environ` are refused. A selected project `.env`, `--env-file` or service `env_file:` resolving outside the project directory, including through a symlink, is read for Compose resolution but every value from it is withheld. Key names, file, line and the withholding reason remain visible (`docs/limits.md`).

### Host-shell allowlist

The source-level environment view lists only these names (if set):

- `COMPOSE_FILE`
- `COMPOSE_PROJECT_NAME`
- `COMPOSE_PROJECT_DIR`
- `COMPOSE_PROFILES`
- `COMPOSE_ENV_FILES`
- `COMPOSE_IGNORE_ORPHANS`
- `COMPOSE_CONVERT_WINDOWS_PATHS`
- `COMPOSE_PARALLEL_LIMIT`
- `COMPOSE_ANSI`
- `COMPOSE_STATUS_STDOUT`
- `COMPOSE_PROGRESS`
- `DOCKER_HOST`
- `DOCKER_CONTEXT`
- `DOCKER_CERT_PATH`
- `DOCKER_TLS_VERIFY`
- `DOCKER_API_VERSION`

Anything else in the shell is **not** listed there. The other reads of the process environment are by exact name:

- **Referenced variables.** Interpolation (`${VAR}`) and container-environment pass-through (`- KEY`, `KEY:`) look up the names your Compose files reference, and nothing else. Their values are classified and redacted like any other value.
- **Shell detection** for `doctor`: `SHELL` on Linux and macOS; `PSModulePath`, `POWERSHELL_DISTRIBUTION_CHANNEL` and `ComSpec` on Windows. Only the shell name is reported.
- **GitHub Actions output** for `check --github`: `GITHUB_WORKSPACE`, `GITHUB_STEP_SUMMARY`, `COMPOSELENS_JSON_PATH`, `COMPOSELENS_SARIF_PATH`, `COMPOSELENS_GITHUB_SUMMARY` and `COMPOSELENS_FAIL_ON` (output paths and the gate level; values are not printed except as artifact file names).

The `docker compose` subprocesses that `doctor`, `differential` and `report` start inherit the process environment, as any child process does; their output is redacted before it is shown.

## Secret-safe output

- Keys matching secret patterns (`*TOKEN*`, `*PASSWORD*`, `*SECRET*`, `*KEY*`, and related forms) are redacted.
- Configuration keys are public when their first or last word is one of: `TTL`, `SECONDS`, `MINUTES`, `HOURS`, `DAYS`, `EXPIRY`, `EXPIRES`, `LENGTH`, `MIN`, `MAX`, `COUNT`, `LIMIT`, `TIMEOUT`, `INTERVAL`, `BACKEND`, `PROVIDER`, `TYPE`, `MODE`, `POLICY`, `ROTATION`, `ENABLE`, `ENABLED`, `DISABLE`, `DISABLED`, `REQUIRED`, `HEADER`, `DIR`, `PATH`, `ISSUER`, `AUDIENCE`, `ALGORITHM`, `FORMAT`, `PREFIX`. Word boundaries are underscores, hyphens, dots and camelCase transitions. Thus `TOKEN_TTL_SECONDS`, `PASSWORD_MIN_LENGTH`, `SECRET_BACKEND`, `TOKEN_EXPIRY`, `ENABLE_PASSWORD_RESET`, `API_KEY_HEADER`, `SECRETS_DIR` and `TOKEN_ISSUER` show ordinary setting values. Substrings such as `MODEL` do not match `MODE`, and a qualifier in the middle of a key alone does not qualify it. Credential keys such as `DB_PASSWORD`, `API_TOKEN` and `SECRET` retain their protections; `PASSWORD_FILE` retains its existing file-reference handling. Secret-shaped values and secret-named parent mappings still withhold values under setting keys.
- The rule applies to every mapping key on a value's path, not only the last one: `x-credentials.api_token.value` and `x-auth.password.current` are secret because `api_token` and `password` are. Compose structure is not read as a secret name: the top-level section, the resource name under `services`, `networks`, `volumes`, `configs` and `secrets`, and a service's `secrets:` reference list. A `.env` variable with a neutral name is withheld wherever it is shown once its value feeds such a field.
- Secret words count anywhere in a key, including camelCase boundaries: `SMTP_PASS_PROD`, `DSN_PRIMARY`, `dbPwd`, `mysqlPw`, `REDIS_AUTH`, `NPM_AUTH`, `URL_SIG`, `SESSION_COOKIE_SIGNING` and `PASSWORD_SALT` are secret. Ordinary option combinations such as `COOKIE_SECURE`, `COOKIE_DOMAIN`, `DSN_TIMEOUT` and `PASS_THROUGH_MODE` stay readable, as do `STOP_SIGNAL` and `BYPASS_CACHE`.
- Service dependency names under `depends_on` and network attachment names under `networks` are structural too. A name such as `password-reset` or `token-net` does not make its condition or priority secret. Boolean values under setting keys such as `AUTH_ENABLED: "true"` and the recognized option `FIRST_PASS: "on"` are visible. `FIRST` alone is not a setting qualifier: `FIRST_PASSWORD` still names a credential. Short boolean and numeric options under other ambiguous keys (`ENABLE_COOKIE: "1"`, `x-sig: {enabled: true}`) stay withheld without requiring a short-secret override. Explicit credential keys such as `PASSWORD` retain the refusal below. Secret-shaped values remain withheld under every setting key.
- Public identifiers remain readable under non-secret keys: UUIDs, labelled image digests, image tags containing a 40-hex revision, and 40-hex values under commit/revision/SHA/tag keys. `KILL_SIG: SIGTERM` and `STOP_SIG` signal names are readable. A hex value under an unrelated key can still be a credential; a secret-named field always withholds its value.
- Values that look like probable secrets (PEM, AWS-style keys, common token prefixes, JWT-shaped strings, **URI/DSN userinfo passwords**, and URI query keys classified by the same secret-key rules as env names — including `access_token`, `refresh_token`, `auth_token`, `id_token`, `client_secret`, `access_key`, `secret_key`, `private_key`, `api_key`, `password`, `passwd`, `pwd`, `passphrase`, and hyphen/underscore equivalents) are redacted even if the enclosing key name is benign. Ordinary credential-free URLs such as `postgres://localhost:5432/app` and ordinary pagination keys such as `page` / `sort` are not treated as secret. `page` is not treated as `pwd`.
- Generated keys are secret by shape: mixed letter/digit runs of 32 or more characters, high-entropy mixed runs of 24–31 characters, and long high-entropy letter runs with frequent case changes. A name followed by a number, such as a folder `BuildCache2026`, is not.
- A value with spaces is read word by word: a `KEY=VALUE` word with a secret key (`-Djavax.net.ssl.keyStorePassword=…`, `--password=…`), the word after a secret-named flag (`--token VALUE`; `--token-file PATH` names a file and is shown), a secret-named header (`Authorization: …`, `X-Api-Key: …`), the credential after `Bearer` or `Basic`, and any word that is itself secret-shaped. In a list such as `command: ["--token", "VALUE"]` the item after a secret-named flag is secret. Only the secret words are guard material.
- Argument pairs include `--auth VALUE` and `-u`/`--user user:password`. A database client followed by `-p VALUE`, or a nonnumeric value after `-p` in an argv list, is withheld; an ordinary port pair such as `-p 8080` remains readable.
- As a last line of defence the pre-write guard refuses output that still contains a run shaped like a generated key even when no rule classified it (exit `4`). Labelled digests and fingerprints (`sha256:…`, `hmac-sha256:…`, CSP `sha384-…`) are exempt.
- Comparable fingerprints are emitted so two sources in **the same invocation/report** can be checked for equality without exposing the value. The HMAC key is generated with `crypto/rand` once per CLI run. Fingerprints are **not** comparable across invocations and are not a stored secret. The public JSON field remains `fingerprint` with the `hmac-sha256:` prefix. Optional `--redact` / `composelens.redact.yaml` may set `display: redacted` so withheld rows show `[redacted]` instead (`docs/redact.md`). The key material is never emitted.
- Sites may add secret key/value patterns and allowlist **specific** false positives through that overlay. Defaults are unchanged when no config is present. Blanket allowlists are rejected. The overlay applies on every redacting surface (`inspect`, `check`, `explain`, `diff`, `differential`, `report --json`).

- A pre-write guard scans outgoing bytes (stdout and user-controlled error JSON/text) for known secret values and fingerprint-key material and **fails closed** (exit code `4`) if a leak is detected, safety is uncertain, or fingerprint-key generation fails. It searches every representation ComposeLens emits (raw bytes, JSON escaping, the HTML report's data island, HTML text, workflow-command escaping) and the decoded strings of JSON output, so an escaped copy of a secret is caught. Output that still contains a recognized vendor token (GitHub, Slack, AWS, JWT, PEM) in any field, including a path, is refused; diagnostics print such a token as `[redacted]`.
- **Short secrets.** A collected secret value shorter than **6 bytes** (bytes, not characters: `ééé` is 6 bytes and passes; `root` is 4 and does not) cannot be scanned for reliably. Empty values are skipped.
  - Commands whose output can carry project values — `inspect`, `explain`, `diff`, `check`, `differential`, `report` — refuse with exit `4` and the code `safety.short-secret`. The refusal names the key and the file and line of each short value (never the value), with a remediation and this document as its doc link, in the selected format (`composelens.error.v0` with `--json`).
  - `doctor` and `reproduce` carry no project values and do not refuse for a short secret; they still guard long secrets and recognized tokens.
  - What is collected: secret-keyed values in Compose files (after merge, **disabled services included**) and in the selected `.env` / `--env-file` / `COMPOSE_ENV_FILES` and service `env_file:` sources. Moving the value into `.env` does **not** help: it is still collected.
  - The opt-in `--allow-short-secret <KEY>` (repeatable, exact key names only: no wildcards, lists or blanket form) accepts the short value under that key. It skips only the byte scan for that value; redaction stays on, so the value is still withheld in every view and format. ComposeLens prints a warning, and JSON output (including the report data package) records the keys in `allowShortSecret`. A short value that also appears under another, unnamed key still refuses. Without the flag nothing changes. A `--redact` `allowKeys` entry reclassifies a key as public and shows its value; it is not a way to keep a real secret withheld.

- Interpolated Compose-model values are redacted with the same classifier when the variable name or resolved content is secret.
- A field that embeds a secret value is withheld as a whole rather than refusing the output: a secret variable interpolated into a plain field (`command: "mysql -uroot -p${DB_PASSWORD}"`, a healthcheck, `build.args`, an `x-` field, or a base file reached through `extends`), or a YAML anchor whose alias sits under a secret key. The raw form stays visible when it holds only plain references (`-p${DB_PASSWORD}`), so the view still shows where the secret goes in; a raw form with a default or alternate (`${TOKEN:-literal}`) or under a secret-named key is withheld. Secret values shorter than 6 bytes stay under the short-secret rule below.
- Merged field values and overridden contributors are redacted with the same classifier; a secret that wins or loses a merge must not appear in stdout or stderr.
- Profile names that look like secrets are redacted on the profiles surface; merged secrets under profiled services stay redacted.
- Secrets inside files pulled in by `include:` are redacted on interpolation, include, merge, and profile surfaces the same way as secrets in discovered files.
- Secrets inside a service inherited via `extends` are redacted on the extends and merge surfaces the same way.
- Container-environment values (from `environment:` or `env_file:`, including losers) are redacted with the same classifier.
- Inline `secrets.<name>.content` is always withheld. Inline config content is withheld when its resource name is secret-like or its value has a secret shape; ordinary inline configuration remains visible. Resource names otherwise stay structural.
- Nested alternate and required interpolation forms such as `${DB_PASSWORD:+x${DB_PASSWORD}y}` and `${DB_PASSWORD:?must be ${DB_PASSWORD}}` withhold their resolved secret values without refusing the command.
- Canonical dual-form values (ports, volumes, labels, command/entrypoint, healthcheck.test) are redacted with the same classifier on `inspect` and `diff`.
- The fixture harness refuses catalog files that hold credential material (`internal/redact.ContainsSecretMaterial`); fixtures must not store live tokens (`docs/fixtures.md`).
- A privacy/security corpus (`docs/security-corpus.md`): secret-shaped probes (in-process only) must be redacted on every existing output surface, and active content must stay inert. Catalog rows under `fixtures/security/` are structure + rationale; live tokens are never stored in `fixtures/` or in test evidence.
- Text from the project (keys, values, paths) is printed in human output with its control characters shown as escapes: CR and LF as `\r` and `\n`, other C0 controls and DEL as `\xNN`, C1 controls (U+0080–U+009F), bidirectional controls, zero-width characters and the Unicode line separators as `\uNNNN`. A key or value with an embedded newline therefore cannot start a new line, and so cannot start a GitHub workflow command (`::error::`, `::add-mask::`, `::stop-commands::`) in `check`, `inspect`, `explain` or `differential` output. `check --github` escapes annotation data (`%0A`, `%0D`), and the job summary puts every target, message and artifact name in a Markdown code span that the text cannot close, so a key cannot add links, images or blocks.
- After secret checks, the pre-write guard also **neutralizes leftover C0/DEL control bytes** (ANSI/ESC, CR, NUL) in the output buffer so human text cannot drive the terminal. Newlines and tabs are kept. This is extra inertness, not a substitute for redaction.
- Engine adapter captures (`docs/engineadapter.md`) redact `docker compose config` through the same classifier; raw secret-bearing engine output is not stored.
- `differential` withholds displayed secret values (`[redacted]`). The CLI captures the engine side through the adapter, which withholds secrets before the comparison, so a secret row from `composelens differential` or `report` is `uncertain` (certainty `unknown`), never a proven match or divergence. The comparator can fingerprint two raw values in-process (hash never emitted), which is how its verdicts are tested (`docs/differential.md`). Only-internal / only-engine secret rows remain presence facts.
- Doctor's capability map (`docs/enginecap.md`) does not run `config` and therefore does not include resolved engine values.
- `explain` redacts the same secret material on the composed account (effective value, stage values, and losers).
- `explain --all` withholds secret effective values on the graph and redacts secret-shaped strings on the human summary.
- `diff` redacts both sides of a secret change and reports it as changed-by-presence (no values).
- `check` never puts a secret value in a finding message, provenance line, JSON field, or SARIF `message.text`. The fail-closed guard applies to all three formats.

## Untrusted input

Compose YAML, JSON, `.env`, and env-files are data. ComposeLens parses them; it does not execute them. The parser/loader applies resource bounds and typed diagnostics (`docs/parser.md`, `docs/limits.md`); hostile input must not panic, hang, or leak secrets in error text.
