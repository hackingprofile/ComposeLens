# Changelog

## [0.1.0]

### Added

- Local Compose inspection with ordered source files, YAML locations and per-run keyed fingerprints.
- Compose interpolation, multi-document files, include and mapping-form extends, multi-file merge, profiles and container-environment precedence.
- Canonical short/long ports, volumes, labels, commands, entrypoints and healthchecks.
- `explain` for a target and `explain --all` for a provenance graph with field-specific source chains.
- `diff` for two profile or environment selections and `differential` against local `docker compose config`.
- `check` with rules CHK01–CHK06, severity gates, expiring policy exceptions, JSON, SARIF and GitHub annotations.
- Remaining findings at or above the configured severity gate exit `6`; a below-gate result exits `0`.
- A composite GitHub Action that builds from source; the example workflow checks the included demo project.
- Offline JSON and interactive HTML reports with keyboard navigation, local assets and a restrictive content security policy.
- `reproduce` to print the selected Compose command and `doctor` for engine and platform metadata.
- `doctor` recognizes the Compose v2+ engine family; behavior outside the documented comparison scope remains unknown.
- Optional redaction patterns and specific allowlists; defaults require no configuration or hosted service.
- Shared input, file, parser-depth and engine-output bounds with typed diagnostics.
- Go 1.27.3 as the minimum build toolchain.

### Fixed

- Secret classification covers nested mappings, camelCase credential keys, credential words anywhere in a key, argument pairs, embedded passwords and generated-token shapes.
- Resource names are structural. Short boolean and numeric options under ambiguous keys stay withheld without refusing the command; explicit short credentials retain the documented refusal and exact-key override.
- Public revision identifiers, image digests, UUIDs and supported signal names remain readable under non-secret keys.
- Selected `.env`, `--env-file` and service `env_file:` sources resolving outside the project directory are read for resolution with every value withheld, including through symlinks. Key, file, line and reason remain visible.
- Inline secret content and sensitive config content are withheld. Nested alternate/required interpolation and aliased secret values retain sensitivity through container-environment resolution.
- Every human output surface escapes project control characters, including target values, include paths and engine command lines. GitHub annotations and Markdown summaries escape their data for their respective formats.
- Extends shadow chains name only files that define the field. Inherited values retain their actual file and line.
- Short-bind comparisons accept the engine's implied `create_host_path=true`; explicit `false` remains distinct. POSIX backslashes remain literal filename characters.
- Missing projects, empty projects, unsupported input forms, special files and exceeded bounds have explicit failure states.
- `doctor` reports the shell name alone. Support bundles refuse existing files and links; artifact outputs refuse symlinks.
- Reports and differentials skip remote-include capture unless `--allow-network` is selected. `report --no-engine` runs no Docker command.
- The output guard checks known secrets in every emitted representation and rejects unclassified credential shapes. Labelled digests and identified public revisions do not bypass known-secret checks.

### Limits

- Long-form include `env_file` and `project_directory`, string-form extends, Dockerfile environment and `docker compose run -e` are not applied.
- Nested interpolation is bounded at depth eight. Relative bind paths, engine-injected default networks and shell/exec representation differences carry documented classifications where supported; some shell-command tokenization differences can remain divergent.
- Engine-withheld secrets are uncertain comparisons. ComposeLens does not upload SARIF, start containers, pull images or publish artifacts.

Licence Apache-2.0 (see LICENSE and NOTICE).
