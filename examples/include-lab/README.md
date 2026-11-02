# Include lab

Local demonstration of ComposeLens top-level `include:` (after interpolation, before merge and profiles).

This is **not** `extends`, container-environment precedence, or `docker compose config` parity. Long-form `env_file` and `project_directory` are recorded as unknown extras and are **not** applied.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/include-lab
```

Windows PowerShell:

```powershell
# short form + including-file override
../../composelens.exe inspect -f compose.yaml
# long form
../../composelens.exe inspect -f long.yaml
# multiple includes in order
../../composelens.exe inspect -f multi.yaml
# nested include
../../composelens.exe inspect -f nested.yaml
# cycle: typed state=cycle, does not hang
../../composelens.exe inspect -f cycle-a.yaml
../../composelens.exe doctor
```

Unix: same commands with `../../composelens`.

Expected:

| File | What inspect should show |
| --- | --- |
| `compose.yaml` | `include` graph `commons.yaml` `state=ok`; `services.web.image` = `overridden` (including file); `hostname` = `from-commons` with include chain |
| `long.yaml` | long-form `path` loaded; `web.image` from commons |
| `multi.yaml` | includes `a.yaml` then `b.yaml`; image `three`; hostname `from-a` |
| `nested.yaml` | compose → mid → inner; three services |
| `cycle-a.yaml` | `hasCycle=true` and a ref `state=cycle` |
