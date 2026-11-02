# Explain

`composelens explain <target>` answers one question: **where did this one effective value come from, through every stage that actually touched it?**

It is a **composition/presentation** surface. It does not re-derive interpolation, include, extends, merge, profiles, or container-environment semantics. It reads the provenance those stages already produce and prints them in resolution order. The whole-model graph is a separate additive surface (`explain --all`, `docs/graph.md`).

`inspect` stays a labeled source-level view. Explain is additive.

## Targets

| Form | Kind | Example |
| --- | --- | --- |
| service name | service | `web`, `web.api` |
| dotted field path | field | `services.web.image`, `services.web.api.image` |
| `service:VAR` | container-environment variable | `web:COLOR`, `web.api:FOO` |

Service names are YAML mapping keys. Paths stay `services.<name>.<field…>`. A service whose name looks like a path (for example `services.web`) is that service; it is not reparsed as another service's field. A field path is the merge field of its owning service, so `services.web.image` stays `web`'s image when a service named `web.image` also exists. `service:VAR` is recognized before a `services.` prefix, so `services.web:APP_ENV` is an environment target on service `services.web`, not a service named `web:APP_ENV`. A string that matches more than one entity is typed `absent` (reason: target matches more than one entity) rather than guessed. Dotless paths are unchanged.

`explain` without a target and without `--all` is a usage error (exit 2), not `unsupported`.

A target that does not exist is typed `absent`, with an empty stage list. Nothing is fabricated.

## Stage order

Only stages that apply to the target are included, in this order:

1. interpolation (raw expression → resolved value + interpolation source)
2. include (include-chain of the winning file, when longer than one hop)
3. extends (inherited / override / concat origin + extends-chain)
4. merge (winning file + overridden contributors)
5. profiles (enabled/disabled and why)
6. container-environment (for `service:VAR`: winner + ordered losers)

The account ends at the **final effective value**. `unknown` / `unsupported` / `absent` from an underlying stage is carried through.

## JSON

Schema: `composelens.explain.v0`.

Stable keys: `schema`, `product`, `version`, `disclaimer`, `target`, `state`, `stages`, `effective`, `secret`, `finalStage`, `certainty`, `evidence`.

A stage that has a source location carries `line` and, when the winning value node is on that line, `column` (the merge stage: the winning file; the container-environment stage: the winning `environment:` or `env_file` line). Both are omitted when unknown, for example for a synthesized override mapping. The human view prints them as `at=FILE:LINE[:COLUMN]`.

`inspect` JSON (`composelens.inspect.v0`) does not gain explain fields.

## Secrets

Secret values are redacted through `internal/redact`. On a secret stage, each overridden contributor keeps its source label and withholds the value (`overridden: env-file <path> [redacted]`, `overridden: <file> override [redacted]`); losers are guard material like the winner. Fail-closed output guard still applies. Synthetic secret probes run in-process and are not stored with test evidence.

## Not this command

- Policy engine / custom rules, HTML report, SARIF **upload**
- Engine differential
- Recursive interpolation
- Changing interpolation through container-environment resolution behavior

The whole-model graph is `explain --all` (`docs/graph.md`). `check` is a separate command (`docs/check.md`).
