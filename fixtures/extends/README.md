# Fixtures for `extends`

| Directory | Role |
| --- | --- |
| `same-file/` | Mapping `extends.service` in the same Compose file; environment override |
| `cross-file/` | `extends.file` + `extends.service`; local image override |
| `relationship/` | Base has `depends_on` / `container_name` — must not be copied |
| `cycle/` | `a` extends `b` extends `a` (typed cycle, no hang) |
| `short-form/` | String `extends: common` recorded `unsupported` (Compose Spec requires a mapping) |

Resolution: interpolate the file → resolve `extends` per service → include expansion of that file → merge → profiles.
