# Precedence lab

Non-secret demo used by the quickstart (`docs/quickstart.md`). Product version **0.1.0**. Licence: Apache-2.0.

Three places a value can live: `compose.yaml`, `compose.override.yaml`, and `.env` (plus optional `--env-file extra.env`). ComposeLens **does** resolve interpolation, merge the overlay, and report container-environment winners (`inspect`, `explain`, `check`). It is not an alternate Compose engine.

Prefer running from the **repository root** with `--project-directory` so you do not have to guess `../` vs `../../`:

```bash
go test ./...
go build -o composelens.exe ./cmd/composelens
.\composelens.exe doctor --json --project-directory examples/precedence-lab
.\composelens.exe inspect --json --project-directory examples/precedence-lab
.\composelens.exe inspect --env-file examples/precedence-lab/extra.env --json --project-directory examples/precedence-lab
.\composelens.exe explain --all --project-directory examples/precedence-lab
.\composelens.exe check --project-directory examples/precedence-lab
.\composelens.exe report --json --project-directory examples/precedence-lab
```

Unix: `go build -o composelens ./cmd/composelens` then `./composelens …`.

The test helper `TestDocumentedQuickstartBinaryPath` still accepts the older `cd examples/precedence-lab` + `../../composelens.exe` form.

`APP_ENV` appears in `.env` and, with `--env-file extra.env`, also in `extra.env`. CLI `--env-file` **replaces** project `.env` for interpolation (Docker Compose v5.4.0).

Do not put real secrets in this directory.
