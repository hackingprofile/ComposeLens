# Service profiles

ComposeLens decides which **merged** services are enabled under the active profile set. This is not container-environment precedence or a provenance graph.

## Order of operations

Discovery → per-file interpolation → include expansion → extends → multi-file merge → **profile activation** → container environment.

## Active profile set

| Source | When it applies |
| --- | --- |
| `--profile <name>` (repeatable) | If any `--profile` flags are present, they **are** the active set (first occurrence wins). |
| `COMPOSE_PROFILES` | Comma-separated names from the process environment, used **only when no `--profile` flags are given**. Spaces around commas are trimmed. |

The profile name `*` (`--profile '*'` or `COMPOSE_PROFILES=*`) activates every profile, as in Compose; a service then reports `enabled by profile *`.

This follows the general Compose CLI rule that command-line flags outrank `COMPOSE_*` environment variables. `--profile` does **not** union with `COMPOSE_PROFILES`. Each active profile is labeled `flag` or `COMPOSE_PROFILES`.

## Service rules

| Service | Enabled when |
| --- | --- |
| No `profiles:` key | Always (`no-profiles (always on)`). `profiles: !reset` is treated as the key absent. |
| `profiles:` list | Iff **at least one** listed name is active (`enabled by profile X (source: …)`). |
| Listed but none active | Disabled (`disabled — none of its profiles {…} are active`). |
| `depends_on` of an enabled service, target has **no** `profiles:` or an **active** own profile | Already enabled by those paths (`proven`). Unchanged. |
| `depends_on` of an enabled service, target is **profiled and none of its profiles are active** | **Not** auto-enabled. Stays not-enabled-by-profiles with an advisory reason and certainty `unknown` / evidence `unsupported`. Official Compose profiles docs do not document silent auto-enable; they tell the user to put the dependency in the same profile, start it separately, or leave it unprofiled. Engine behavior is unverified here. Missing targets are ignored (no fabricated service). |
| Mapping-form `profiles:` | `unsupported` / certainty `unknown` — not guessed. |

Profiles on networks, volumes, and other non-service objects are **unknown/unsupported**. Profiles run on the model **after** `include:` expansion and `extends` resolution.

## Surface

`composelens inspect` keeps `view: source-level`, interpolation, and merge sections, and adds `activeProfiles` / `profileServices` / `profilesDisclaimer`. Secret values in the merged model stay redacted; secret-shaped profile names are redacted too.
