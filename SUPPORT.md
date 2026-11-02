# Support

ComposeLens **0.1.0** is a **local-first** CLI. Licence: Apache-2.0 (see `LICENSE` and `NOTICE`).

## How to get help

- Bugs: GitHub issues using `.github/ISSUE_TEMPLATE/bug.yml` (reproducible evidence required)
- Features: `.github/ISSUE_TEMPLATE/feature.yml`
- Security: `SECURITY.md` (private)

On an internal error (exit 1) or a recovered panic, ComposeLens prints telemetry-free crash guidance and does **not** send data anywhere. Generate a diagnostic bundle with `composelens doctor --bundle composelens-support.json` (`docs/support.md`). Never attach secrets or Compose contents.

## What ComposeLens can help with

The full local CLI: `doctor`, `inspect`, `explain` / `--all`, `diff`, `check` (human / JSON / local SARIF / `--github`), `differential`, `reproduce`, `report --json` / `--html`, `version`. Redaction defaults apply. See `docs/cli.md` and `docs/quickstart.md`.

## What we cannot help with yet

A hosted HTML report, a general policy engine, SARIF **upload** / GitHub code-scanning, GitHub Marketplace listing, signed release binaries, hosted SaaS usage.

## Compatibility

See `docs/compatibility.md`. Recognized Compose v2+ family vs verified pin Docker Compose **v5.4.0** / Engine **29.7.2**. We do not claim untested platforms or an unverified version matrix.
