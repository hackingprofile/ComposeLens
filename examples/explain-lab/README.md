# Explain lab

Local demonstration of ComposeLens **single-target** end-to-end account assembled from interpolation, include, extends, merge, profiles, and container-environment stages.

This is **not** a provenance graph. `inspect` stays a source-level view. Demo values are not secrets.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/explain-lab
```

Windows PowerShell:

```powershell
../../composelens.exe explain web:COLOR -f compose.yaml -f overlay.yaml
../../composelens.exe explain services.web.hostname -f compose.yaml -f overlay.yaml --json
../../composelens.exe explain debug -f compose.yaml -f overlay.yaml
../../composelens.exe explain missing -f compose.yaml -f overlay.yaml --json
../../composelens.exe inspect -f compose.yaml -f overlay.yaml
```

Unix: `../../composelens explain web:COLOR -f compose.yaml -f overlay.yaml`.

Expected (non-secret demo values):

- `web:COLOR` spans interpolation (`${TINT}` → `teal`) and container-environment (winner `environment`)
- `services.web.hostname` is inherited via `extends` and kept by merge (overlay only changes `image`)
- `debug` is disabled by profiles (no `--profile debug`)
- `missing` is typed `absent` with an empty stage list
- `inspect` still reports source-level interpolation, extends, merge, profiles, and container environment
