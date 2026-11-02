# Telemetry-free support surface

ComposeLens does **not** send crashes, diagnostics, or project data anywhere. There is no telemetry, crash reporter, auto-update, or network upload.

## Crash guidance

On an **internal error** (exit `1`) and on a **recovered panic** in `main` (also exit `1`), stderr includes a sanitized block that:

- states that nothing is sent anywhere
- points at `.github/ISSUE_TEMPLATE/bug.yml`
- tells you to generate a diagnostic bundle (never paste secrets or Compose contents)

The panic value is **not** printed.

## Diagnostic bundle

```
composelens doctor --bundle composelens-support.json
```

Writes **environment/diagnostic metadata only**: product/version, platform, engine detection, engine capability window, and the implemented/deferred feature lists. It does **not** read Compose files, env files, or project directory contents. It therefore cannot include source values or secrets from the project.

`--bundle` is **doctor only**. The bundle is always a new file: an existing file or a symbolic link at the path is refused with `output-exists` (exit 3) and left untouched. Empty `--bundle=` is usage (exit 2). `--json` and `--bundle` are mutually exclusive so `doctor --json` stdout bytes stay unchanged. The bundle holds detection metadata only (no project values); it is guarded against the values withheld from that metadata and against recognized tokens, and a write error never prints a token from the bundle path (`docs/enginecap.md`, `docs/privacy.md`).

Attach the JSON file to a bug report. Do not attach Compose files with secrets.

See `docs/cli.md` (flag applicability contract) and `SUPPORT.md`.
