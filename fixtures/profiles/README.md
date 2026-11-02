# Fixtures for service profiles.

| File | Role |
| --- | --- |
| `official.yaml` | Core `web` (no profiles); `debug` (single); `worker` (debug+tools) |
| `depends.yaml` | Core `web` `depends_on` profiled `db` (inactive-profiled dependency is **not** auto-enabled) |

Activation uses the **merged** model. `--profile` flags outrank `COMPOSE_PROFILES` when flags are present.
