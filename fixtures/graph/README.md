# Graph fixtures

`shadow-chain/` is a multi-stage provenance case:

- interpolation: project `.env` `TINT` is shadowed by `--env-file extra.env`
- container environment: `overlay.env` `COLOR` is shadowed by `environment: COLOR: ${TINT}`
- whole-model: services `web` and `worker` are both present

Demo values are not secrets. Secret-through-a-chain probes run in-process and are not stored here.
