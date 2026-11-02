# Untrusted-input limits

ComposeLens treats Compose files, env files (CLI `--env-file`, project `.env`, and service `env_file:`), policy files, redaction configs, and engine `config` capture as **untrusted input**. One CLI invocation shares a single aggregate budget so split or transitive loads cannot exceed the intended total.

Per-file 1 MiB bounds remain. Ordinary projects (a handful of small files) are unchanged.

| Cap | Constant | Value | Charged by |
| --- | --- | --- | --- |
| Per file | `safety.MaxFileBytes` | 1 MiB | every disk read (`discover`, `include`, `extends`, `--env-file` / project `.env`, service `env_file:`, `--policy`, `--redact` / `composelens.redact.yaml`) |
| Aggregate bytes | `safety.MaxTotalBytes` | 4 MiB | unique charged paths **plus** engine stdout/stderr bytes in the same invocation |
| File count | `safety.MaxTotalFiles` | 256 unique paths | disk files only (engine streams do not count as files) |
| Engine stream | `safety.MaxEngineOutputBytes` | 4 MiB per stdout or stderr | `docker compose version` / `config` capture (`internal/engineadapter`) and `doctor` version detection (`internal/engine`; overflow refuses `doctor` and `doctor --bundle` with exit 3) |
| Include expansion | `safety.MaxIncludeExpansions` | 256 included files per root file, every repeated reference counted | `include:` expansion; overflow is `include-expansion-limit`, exit 3 |
| Rendered HTML | `report.MaxHTMLBytes` (= `MaxTotalBytes`) | 4 MiB | `report --html` output; overflow is `input-total-too-large`, exit 3 |

Exceeding a cap returns `internal/safety.ParseError` with a stable code (`input-too-large`, `input-total-too-large`, `input-too-many-files`, `engine-output-too-large`, `include-expansion-limit`) and CLI exit **3** (`Input`) **before** resolution/analysis continues. Diagnostics do not echo file contents or secret-shaped paths.

The same path is charged once (discover + later include/extends/env/policy/`env_file:` re-read is a no-op). Engine streams are charged on every capture in that invocation.

See `docs/parser.md` for YAML walk bounds (depth, aliases, node count, timeout).

## Special files and files outside the project

- **Special files are refused.** A device, FIFO, socket, or a path in a kernel pseudo-file system (`/proc`, `/sys`, `/dev` on Linux and macOS; `NUL`, `CON` and named pipes on Windows) is never opened, wherever it is named: `-f`, `--env-file`, project `.env`, `include:`, `extends:` or a service `env_file:`. The run stops with `input-not-regular-file` and exit **3** (`Input`). A FIFO therefore cannot block ComposeLens, and `env_file: /proc/self/environ` cannot dump the process environment.
- **Service `env_file:` outside the project directory is read but withheld.** When a service `env_file:` resolves outside the project directory (an absolute path, `..`, or a symlink that points outside), ComposeLens still reads it, as Compose does, so precedence stays correct, but **every value from that file is withheld** in every view and format. Key names, file and line stay visible, and the file's reason says `env_file is outside the project directory; its values are withheld`. A file inside the project directory is shown as before.
- **Selected interpolation files have the same boundary.** A project `.env`, `--env-file` or `COMPOSE_ENV_FILES` entry resolving outside the project directory is read but all its values and interpolated uses are withheld. This includes a project `.env` symlink pointing outside and that same link selected as service `env_file: .env`. Source keys, file and line remain visible with the reason `environment file is outside the project directory; its values are withheld`. An unselected `.env` is not read.

## Maximum-input policy

This budget **is** the product's maximum-input policy. A representative large-but-legal project (`fixtures/perf/large`, dozens of services, well under 4 MiB) is analyzed normally. An over-budget input is refused with a typed diagnostic (`input-too-large` / `input-total-too-large` / `input-too-many-files` / YAML walk caps) and CLI exit **3** **before** check/report analysis. Diagnostics are secret-safe (no file contents, no secret-shaped paths).

## Interactivity threshold

On a current desktop-class machine, `check` and `report` (`--json` / `--html`) of `fixtures/perf/large` must complete in **under 2 seconds** wall each. A benchmark run records the actual machine and `ns/op` from `go test -bench`.
