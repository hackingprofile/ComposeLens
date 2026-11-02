# Graph lab

Local demonstration of ComposeLens **whole-model provenance graph** with **shadow-chains**, assembled from existing stage outputs (`docs/graph.md`).

This is **not** a new resolver and **not** an engine differential. Single-target `explain` is unchanged. Demo values are not secrets.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/graph-lab
```

Windows PowerShell:

```powershell
../../composelens.exe explain --all --env-file extra.env
../../composelens.exe explain --all --env-file extra.env --json
../../composelens.exe explain web:COLOR --env-file extra.env
```

Unix: `../../composelens explain --all --env-file extra.env`.

Expected (non-secret demo values):

- `web:COLOR` interpolation: `--env-file extra.env` supplies `TINT` and wins. `--env-file` **replaces** the project `.env` (`docs/interpolation.md`), so `.env` is not read and is not a loser in the chain (it is listed as an unapplied source by `inspect`)
- `web:COLOR` container-environment: `overlay.env` `COLOR` shadowed, `environment:` wins
- `worker` is present in the same graph (whole-model coverage)
- `explain web:COLOR` without `--all` still emits `composelens.explain.v0`
