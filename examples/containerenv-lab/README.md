# Container-environment lab

Local demonstration of the **container** environment built from `environment:` and `env_file:`, after interpolation / include / extends / merge / profiles.

This is **not** Compose interpolation (which substitutes `${VAR}` in Compose YAML text). Dockerfile `ENV` is not read. `docker compose run -e` is out of scope.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/containerenv-lab
```

Windows PowerShell (set a host value for pass-through):

```powershell
$env:DEBUG = "from-shell"
../../composelens.exe inspect -f compose.yaml
../../composelens.exe inspect --json -f compose.yaml
../../composelens.exe doctor
```

Unix: `DEBUG=from-shell ../../composelens inspect -f compose.yaml`.

Expected (non-secret demo values):

- `COLOR` wins from `environment:` (`from-compose`); `a.env` then `b.env` are losers
- `SHARED` wins from later `env_file` `b.env`
- `DEBUG` wins from the host shell via list-form pass-through
- Interpolation section still shows Compose-file `${}` separately, if any
