# Baseline corpus

Small Compose projects for primary interpolation grammar and container-environment precedence. Each row is declared in `fixtures/catalog.yaml`. Expected engine results are pinned to live `docker compose` **v5.4.0** (daemon up) via `composelens differential`.

Do not store live tokens here. Secret-shaped probes run in-process.

`interpolation.corpus.escape` is live-pinned **matched** at the engine runtime (`$VAR`). `interpolation.corpus.default-ref` is **matched**: the reference inside the default expands to `other-value`, as in the engine.
