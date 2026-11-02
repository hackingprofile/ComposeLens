# Check fixtures

Fixed ruleset cases for `composelens check`. Demo values are not secrets.

| Directory | Check | Expected |
| --- | --- | --- |
| `clean/` | (none) | zero findings |
| `secret-inline/` | CHK01 | warning on `web:API_TOKEN` |
| `inline-default/` | CHK01 | warnings on `web:DIRECT_SECRET` and `web:DEFAULT_SECRET` (`${UNSET_VAR:-demo-hidden}`) |
| `overlay-win/` | CHK01 | warning on `web:API_TOKEN` when `overlay.yaml` wins (CLI `--file` both; catalog assertion is files-exist) |
| `external-ref/` | (none) | `${SECRET_ENV}` is not an inline secret |
| `nonsecret-default/` | (none) | `${UNSET_VAR:-plain}` is not a secret |
| `required-unset/` | CHK02 | error on required interpolation |
| `profiled-dep/` | CHK03 | warning on profile-gated `db` |
| `missing-include/` | CHK04 | error on absent include path |
| `missing-extends/` | CHK04 | error on absent extends service |
| `env-shadowing/` | CHK05 | info on `web:COLOR` |

Adversarial secret probes run in-process and are not stored here.
