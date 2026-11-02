# Policy loading + assertion gate

`composelens check --policy <file>` loads an external **schema-validated** policy overlay, then runs the existing CHK01–CHK06 ruleset. Invalid policies fail **before** Compose analysis (exit `3`) with a typed `policy:` diagnostic. Without `--policy`, the fixed ruleset **findings** are unchanged (`fixed-v0`); `check` still applies the default **error** severity gate to the process exit code (`docs/check.md`).

This is not a general policy engine. `policy-engine` stays deferred on `doctor`. `threshold` is not a `composelens.policy.v0` field.

## Schema `composelens.policy.v0`

YAML or JSON. Allowed top-level fields: `schema` (required), `gate`, `rules`, `exceptions`.

```yaml
schema: composelens.policy.v0
gate: error
rules:
  - id: CHK01
    severity: error
  - id: CHK05
    enabled: false
exceptions:
  - rule: CHK03
    expires: "2099-12-31"
```

- `gate` is `error` (default), `warning`, or `info`. Findings at that severity or higher fail the check (exit `6`) unless waived. Unknown `gate` values fail at load (`invalid-rule`).
- `rules` may be a list of objects (`id` required) or a map keyed by rule id.
- Overlay: unlisted rules keep the fixed defaults. `enabled: false` drops that rule's findings. `severity` replaces the default.
- `threshold` is **not** part of `composelens.policy.v0`. It is an unknown field and fails before analysis.
- Duplicate JSON or YAML keys at any policy-object depth fail before analysis (`duplicate-field`). The duplicated value is not echoed.
- `exceptions` load only when `expires` is a **future** `YYYY-MM-DD` (or RFC3339) date. Missing, invalid, or past/today dates fail at load time.
- At apply time, a loaded exception **waives** matching findings **only while UTC today is strictly before `expires`**. On or after that date the finding returns and can gate. Time comes from `policy`’s injectable UTC clock.

Unknown fields, unknown rule ids, unknown schema versions, duplicate keys, multiple documents, trailing content, oversized or invalid UTF-8 input, and malformed files are invalid.

## Bounds

Policy files are untrusted input. `composelens.policy.v0` uses the project safety constants (`docs/parser.md`, `docs/limits.md`): **1 MiB** maximum file size (`safety.MaxFileBytes`), nesting depth **64**, and **50 000** nodes. Policy bytes are also charged against the **shared 4 MiB / 256-file invocation budget**. Load refuses an oversized file from size metadata before allocating the whole contents, then reads at most one byte past the cap. JSON and YAML decoding share those depth/node budgets. YAML anchors, aliases, merge keys (`<<`), custom tags, and cycles are rejected (`unsupported-construct`). Exactly one YAML or JSON document is accepted; a second document or trailing non-whitespace fails before analysis.

Validation is deterministic: schema presence/version is checked first; remaining mapping keys and rule-map ids are examined in lexicographic order; exception lists keep list order. Identical policy bytes produce the same first diagnostic.

## Apply

`check` still evaluates the fixed ruleset, then applies the overlay: disabled findings are omitted; waived findings remain with an honest marker (JSON `waived`, SARIF `suppressions`, human `waived` section) and SARIF physical locations; remaining findings use policy severities. Human / JSON / SARIF stay valid and agree. JSON `ruleset` becomes `policy-v0` and `policy` names the schema. JSON `gate` names the active gate.

## Exit codes

| Code | When |
| --- | --- |
| `0` | Valid policy applied and no remaining finding meets the gate |
| `2` | `--policy` on a non-check command, missing `--policy` value, explicit empty `--policy=` / whitespace |
| `3` | Invalid or unreadable policy — **no analysis** |
| `4` | Fail-closed output guard |
| `6` | Assertion — a non-waived finding meets the gate (`internal/exitcode.Assertion`) |

Secrets in a policy file are never echoed in diagnostics.
