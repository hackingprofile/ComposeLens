# Profiles lab

Local demonstration of ComposeLens service profiles (after merge).

This is **not** `include`, `extends`, container-environment precedence, or `docker compose config` parity.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/profiles-lab
```

Windows PowerShell — three ways:

```powershell
# 1. default: no profile flags or COMPOSE_PROFILES
../../composelens.exe inspect
# 2. --profile
../../composelens.exe inspect --profile debug
# 3. COMPOSE_PROFILES
$env:COMPOSE_PROFILES = "debug"
../../composelens.exe inspect
Remove-Item Env:COMPOSE_PROFILES
../../composelens.exe doctor
```

Unix:

```bash
../../composelens inspect
../../composelens inspect --profile debug
COMPOSE_PROFILES=debug ../../composelens inspect
```

Expected activation:

| Service | Default | `--profile debug` / `COMPOSE_PROFILES=debug` |
| --- | --- | --- |
| `web` | enabled, no-profiles (always on) | same |
| `db` | disabled, required by `web` via `depends_on` but gated behind inactive profile `{storage}` (certainty `unknown`) | same (storage still inactive) |
| `debug` | disabled | enabled by profile `debug` |
| `worker` | disabled | enabled by profile `debug` |

Active-profile source is `flag` for `--profile` and `COMPOSE_PROFILES` for the env var. `--profile` overrides `COMPOSE_PROFILES` when both are set (command-line flags outrank `COMPOSE_*` environment variables).
