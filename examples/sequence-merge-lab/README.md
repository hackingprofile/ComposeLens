# Sequence-merge lab

Live-validated against Docker Compose v5.x: sequences append, unique resources dedupe by key, `command` replaces.

```powershell
docker compose --project-directory . -f compose.yaml -f overlay.yaml config
go run ../../cmd/composelens inspect --json -f compose.yaml -f overlay.yaml --project-directory .
```
