# README demo

The small two-service project behind the README's `explain` and `check` examples. Demo values are not secrets.

- `.env` sets `APP_ENV=staging`; `compose.yaml` sets `APP_ENV: production` under `environment:`. No service names `.env` in `env_file:`, so `.env` is only an **interpolation source**: it is collected, never injected into the container.
- `API_KEY` has an inline default (`${API_KEY:-…}`) under a secret-shaped key.

From the repository root (Windows; Unix: `./composelens`):

```bash
go build -o composelens.exe ./cmd/composelens
.\composelens.exe explain api:APP_ENV --project-directory examples/readme-demo
.\composelens.exe check --project-directory examples/readme-demo
```

Expected:

- `explain api:APP_ENV`: `production` wins from `compose.yaml` (file and line shown); there is **no** container-environment loser, because `.env` is not injected.
- `check`: one finding, `CHK01` (secret-keyed inline default on `api:API_KEY`), with the value redacted. Exit `0` (a warning is below the default `error` gate).
