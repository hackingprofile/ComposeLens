# Engine capability

ComposeLens records an honest map of **detected Docker Compose engine capabilities**. This is **not** a differential (`docs/differential.md`) and **not** a claim that our model matches `docker compose config`.

Doctor lists `compose-engine-capability` as implemented. `compose-engine-differential` is implemented as `composelens differential` — that is a comparison report, not a claim of engine parity.

## Recognized family vs verified pin

Aligned with `docs/compatibility.md`:

- **Recognized family.** The capability code treats a parsed Compose plugin **major ≥ 2** as in-window. Doctor JSON then sets `engineCapabilities.support` to `"recognized"` and `detail` to `recognized Docker Compose v2+ family; not a verified multi-version matrix`. That is **family recognition** (not Compose v1). It is **not** a claim that every 2.x/5.x engine was tested.
- **Verified pin.** Corpus engine values were recorded with Docker Compose **v5.4.0** and Docker Engine **29.7.2**; live tests run against the installed release and log it (`docs/compatibility.md`).
- Compose **v1** (`1.x`) is **typed `unsupported`** — a clear failure, never a silently-wrong model. Unparseable version strings are `unknown`.
- **Detection metadata is bounded and redacted.** A version is kept only when it matches the version grammar (`[v]MAJOR.MINOR[.PATCH]` with an optional `-`/`+` suffix, at most 64 bytes, never a recognized token); anything else is state `unknown` with the fixed detail "version string not recognized". A failing detection keeps only the first line of its message, with credential pairs, recognized tokens and secret-shaped words withheld, bounded to 160 bytes. Detection output is byte-capped like `config` capture; an overflow refuses `doctor` (and `doctor --bundle`) with exit 3, `engine-output-too-large` (`docs/limits.md`).

The JSON token is `"recognized"`, not a bare `"supported"`.

## Capability map

Unverified engine behaviors are **`unknown`** on this map. Live `docker compose config` success marks `compose-config` as `known`. Interpolation, include, extends, and profiles stay `unknown` here because **doctor does not execute `differential` or `config`** — those capabilities are recognized, not runtime-verified. `composelens differential` reports match/divergent rows instead of rewriting this map (`docs/differential.md`). File-overlay unique-key sequence merge is implemented (`docs/merge.md`); that is not a claim of engine parity.

Doctor reports this summary from **version detection only** (`compose-config` remains `unknown` there — doctor does not run `config`, so it cannot leak resolved secrets). Live captures use `internal/engineadapter`.

## JSON

Schema `composelens.enginecap.v0`, nested on doctor as `engineCapabilities`. Inspect JSON is unchanged.
