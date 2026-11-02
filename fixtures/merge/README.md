# Merge fixtures

Official Compose overlay examples plus issue-derived custom tags.

| File | Role |
| --- | --- |
| `base.yaml` | Earlier file: scalar `image`/`hostname`, environment map A+B, ports list |
| `overlay.yaml` | Later file: scalar override, map deep-merge, ports **append** |
| `third.yaml` | Third overlay: scalar override order (`image` wins last) |
| `reset.yaml` | Issue-derived: `environment: !reset {}` |
| `override.yaml` | Issue-derived: `environment: !override` |

`gopkg.in/yaml.v3` preserves `!reset` and `!override` tags (see `TestResetTag` / `TestOverrideTagReplacesMapping`). Sequence fields **append** (unique-key dedup for ports/volumes/secrets/configs; `command`/`entrypoint`/`healthcheck.test` replace). See `docs/merge.md`.
