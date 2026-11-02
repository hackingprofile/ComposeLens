# Security Policy

ComposeLens treats Compose files, `.env` files, and host environment values as **untrusted input**. The tool must not execute Compose content, must redact secrets by default, and must fail closed if output safety is uncertain.

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |

## What this tool does not do

- It does not talk to a ComposeLens cloud.
- It does not send project files to a model provider.
- It never starts or runs containers, never pulls images, and never transmits Compose files to Docker Hub.

## Docker subprocesses (local CLI)

User-facing Docker CLI use is local and limited to the following. None of these require a ComposeLens cloud or a model provider.

- **`doctor`** may invoke `docker compose version` (and similar detection commands) to read a version string. Detection does not pass the project selection.
- **`differential`** invokes local `docker compose config`, passing your project selection (`--project-directory`, `-f`/`--file`, `--env-file`, `--profile`) so ComposeLens can compare its model to the engine's resolved config. `docker compose config` is **client-side**: it resolves locally and does not require the daemon.
- **`report --json` / `report --html`** invoke the same local `docker compose config` capture with the same project selection to fill the report's differential section. Engine-absent is a typed empty section, not a failure. Captured output passes through the same redaction and fail-closed guard as `differential`.
- **`reproduce`** prints a `docker compose config` command with the same selection flags; it does **not** run that command.

**Network boundary.** ComposeLens itself makes no network calls. Local `docker compose config` needs no network for a local project. A remote include (an `oci://`, Git or `http(s)://` reference under `include:`) would make the engine resolve it over the network, so `report` and `differential` skip the engine capture (engine state `skipped`, with the reason) unless you pass `--allow-network`. `report --no-engine` runs no Docker command at all.

## Reporting a vulnerability

**Do not** file security reports in public issues.

Report it privately through GitHub: open the repository's **Security** tab and choose **Report a vulnerability** (GitHub private vulnerability reporting). The report stays private between you and the maintainers until an advisory is published.

- Do not publish exploit details, raw secrets, or private Compose files.
- Describe the affected command, the input shape (with secrets replaced) and the output you saw.

## Secret handling

If a report involves secrets, include only:

- key names
- source path and line (if safe)
- ComposeLens fingerprints from `inspect --json`
- redacted reproduction steps

Never include the raw secret.

## GitHub security automation

Workflows for CodeQL, dependency review, secret scan, license scan, and OpenSSF Scorecard live under `.github/workflows/`. Enable them in your repository. A protected default branch should require those checks before merge. See `docs/security-automation.md`.
