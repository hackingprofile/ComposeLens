# Diff lab

Local demonstration of ComposeLens **effective-config delta** between two selections over the **same** Compose files.

Both sides run the existing interpolation → include → extends → merge → profiles → container-environment pipeline. This is **not** a provenance graph and **not** an engine differential. Demo values are not secrets.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/diff-lab
```

Windows PowerShell:

```powershell
../../composelens.exe diff
../../composelens.exe diff --right-profile debug
../../composelens.exe diff --left-env-file left.interp.env --right-env-file right.interp.env --json
../../composelens.exe inspect
../../composelens.exe explain web:COLOR
```

Unix: `../../composelens diff --right-profile debug`.

Expected (non-secret demo values):

- `diff` with no left/right selectors is **empty** (identical sides; default `SIDE_FILE` is `left.env`)
- `--right-profile debug` **adds** the `debug` service
- `--left-env-file` / `--right-env-file` **changes** `web:COLOR` (env-file `left.env` vs `right.env`) and **removes** `web:ONLY_LEFT` on the right
- `inspect` and `explain` stay unchanged
