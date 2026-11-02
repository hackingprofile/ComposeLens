# Fixtures for top-level `include:`

Each case is a directory. Paths in `include:` are relative to the including file.

| Directory | Role |
| --- | --- |
| `short/` | Scalar `include: base.yaml`; including file overrides `image` |
| `long/` | Mapping `include: {path: base.yaml}` |
| `long-extras/` | Long form with `env_file` and `project_directory` (loaded `path` only; extras unknown) |
| `multi/` | List of two includes, then including-file override |
| `nested/` | `compose` → `mid` → `inner` |
| `cycle/` | `a.yaml` ↔ `b.yaml` (typed cycle, not a hang) |
| `override/` | Included `hostname` kept; included `image` overridden |

Resolution: parse → interpolate include paths → recurse with cycle/depth guards → merge included models as the base → including file overrides → profiles.
