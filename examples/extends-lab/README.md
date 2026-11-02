# Extends lab

Local demonstration of ComposeLens service `extends` (after interpolation, before merge and profiles).

The Compose Specification requires mapping form `{service, file?}`. String short form is recorded `unsupported` and is not applied. Relationship keys (`depends_on`, `links`, `volumes_from`, `container_name`, and service/container `ipc`/`pid`/`network_mode`/`net`) are **not inherited**.

This is **not** container-environment precedence or `docker compose config` parity.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/extends-lab
```

Windows PowerShell:

```powershell
# same-file extends + local environment override
../../composelens.exe inspect -f compose.yaml
# cross-file extends
../../composelens.exe inspect -f cross.yaml
# relationship keys not copied
../../composelens.exe inspect -f relationship.yaml
# cycle: typed state=cycle, does not hang
../../composelens.exe inspect -f cycle.yaml
../../composelens.exe doctor
```

Unix: same commands with `../../composelens`.
