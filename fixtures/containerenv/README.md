# Fixtures for container environment

| Directory | Role |
| --- | --- |
| `override/` | `environment:` COLOR overrides `env_file` |
| `order/` | two `env_file` entries; later SHARED wins |
| `passthrough/` | list-form `- DEBUG` takes the host shell |
| `multi/` | COLOR in a.env, b.env, and `environment:` — compose wins, files are losers |

Resolution: interpolate → include → extends → merge → profiles → **container environment**.
Dockerfile `ENV` is not read. `docker compose run -e` is out of scope.
