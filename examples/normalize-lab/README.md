# Normalize lab

Two Compose files that mean the same `ports` / `volumes` / `labels` / `healthcheck.test`, plus a command shell vs exec contrast.

From the repository root (Windows):

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/normalize-lab
../../composelens.exe inspect --file compose.short.yaml --json
../../composelens.exe inspect --file compose.long.yaml --json
```

Unix: `go build -o composelens ./cmd/composelens` and run `../../composelens` from this directory.

`inspect` stays source-level. Canonical dual-form fields appear under `normalization`. This is not an engine differential.
