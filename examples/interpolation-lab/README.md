# Interpolation lab

Local demonstration of ComposeLens interpolation (interpolation stage only).

This is **not** merge, container-environment precedence, or `docker compose config` parity.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/interpolation-lab
```

Set interpolation names in the shell (examples, not secrets):

Windows PowerShell:

```powershell
$env:IMAGE = "nginx:1.27-alpine"
$env:HOST = "web.local"
$env:COLOR = "from-shell"
$env:ENTRY = "1"
../../composelens.exe inspect
../../composelens.exe inspect --json
../../composelens.exe inspect --env-file extra.env --json
```

Unix:

```bash
IMAGE=nginx:1.27-alpine HOST=web.local COLOR=from-shell ENTRY=1 ../../composelens inspect
```

`inspect` keeps the source-level view and adds a labeled interpolation section (raw expression, resolved value, source, typed state). `MISSING_REQUIRED` is intentionally unset so the required form surfaces `required-error` without fabricating a value.

Recursive interpolation of default text and of env-file values is deferred.
