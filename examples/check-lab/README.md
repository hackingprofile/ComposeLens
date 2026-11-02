# Check lab

Local demonstration of ComposeLens **fixed ruleset** over the effective model (`docs/check.md`). Not a policy engine, not a provenance graph, and not a SARIF upload.

Demo values are not secrets. Adversarial secret probes run in-process only.

From the repository root:

```bash
go build -o composelens.exe ./cmd/composelens
cd examples/check-lab
```

Windows PowerShell:

```powershell
../../composelens.exe check --project-directory clean
../../composelens.exe check --json --project-directory required-unset
../../composelens.exe check --sarif --project-directory missing-include
../../composelens.exe inspect --json --project-directory clean
../../composelens.exe explain --json web --project-directory clean
../../composelens.exe diff --json --project-directory clean
```

Unix: `../../composelens check --project-directory clean`.

Expected (non-secret demo values):

- `clean` → **no findings**, exit 0
- `secret-inline` → CHK01 warning on `web:API_TOKEN` (value never printed)
- `required-unset` → CHK02 error
- `profiled-dep` → CHK03 warning on `db`
- `missing-include` → CHK04 error
- `env-shadowing` → CHK05 info on `web:COLOR`
- human / `--json` / `--sarif` agree on the finding set; `--sarif` is local SARIF 2.1.0 only
- `check --policy ../../examples/policy-lab/valid.yaml --project-directory env-shadowing` disables CHK05 (`docs/policy.md`)
