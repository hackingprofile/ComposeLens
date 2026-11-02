# Policy lab

Sample `composelens.policy.v0` overlay for `check --policy`. See `docs/policy.md`.

From the repository root:

```powershell
go build -o composelens.exe ./cmd/composelens
./composelens.exe check --policy examples/policy-lab/valid.yaml --project-directory examples/check-lab/env-shadowing
```

`valid.yaml` disables CHK05, raises CHK01 to error, and waives CHK03 until 2099-12-31. Invalid duplicate-key, `threshold`, multi-document, and YAML-construct fixtures live in `internal/policy/testdata/` (not accepted by v0). Policy files are capped at 1 MiB with depth/node bounds (`docs/policy.md`).
