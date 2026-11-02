# Reproduction labs

Three small Compose projects used to show `composelens reproduce` against live `docker compose config` with the installed Compose plugin:

| Dir | What it exercises |
| --- | --- |
| `merge/` | Ordered `-f compose.yaml -f overlay.yaml` |
| `profiles/` | `--profile debug` |
| `envfile/` | `--env-file extra.env` |

Commands reference files and flags only. No live tokens.
