# Regression corpus

Small Compose projects that lock historically tricky behaviors. Each row is `kind: regression` in `fixtures/catalog.yaml` with a **verifiable** `rationale` (`compose-spec` or official Docker `docs` URL — no fabricated GitHub issue numbers). Expected engine results are live-pinned to `docker compose` **v5.4.0**.

Do not store live tokens here. Secret-shaped probes run in-process.
