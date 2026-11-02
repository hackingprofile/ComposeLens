# Merge lab

Local demonstration of ComposeLens multi-file merge (after interpolation).

This is **not** profiles, includes, `extends`, container-environment precedence, or `docker compose config` parity.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/merge-lab
```

Windows PowerShell:

```powershell
$env:KEEP = "from-shell"
../../composelens.exe inspect -f compose.yaml -f overlay.yaml -f reset.yaml
../../composelens.exe inspect --json -f compose.yaml -f overlay.yaml -f reset.yaml
../../composelens.exe doctor
```

Unix:

```bash
KEEP=from-shell ../../composelens inspect -f compose.yaml -f overlay.yaml -f reset.yaml
```

Expected merged fields (non-secret):

| Path | Winner | Value / action |
| --- | --- | --- |
| `services.web.image` | `overlay.yaml` | `redis` (scalar override) |
| `services.web.hostname` | `compose.yaml` | interpolated `from-shell`, kept |
| `services.web.environment.A` | `compose.yaml` | `one` (map keep) |
| `services.web.environment.B` | `overlay.yaml` | `two-b` (map override) |
| `services.web.environment.C` | `overlay.yaml` | `three` (map add) |
| `services.web.ports` | `overlay.yaml` | `[80:80, 443:443, 8080:80]` (sequence **append**) |
| `services.cache.environment` | `reset.yaml` | `!reset` (children dropped) |

Inspect still prints the source-level file list and the interpolation section. Secrets stay redacted.
