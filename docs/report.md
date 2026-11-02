# Report (data package + interactive offline HTML)

`composelens report --json` emits one **self-contained JSON document** (`composelens.report.v0`). `composelens report --html` wraps that same package in a **single offline HTML file** with four keyboard-navigable views and zero remote assets. Neither command recomputes interpolation, merge, identity, findings, or the engine differential.

The **human** report (no `--json` / `--html`) stays reserved and exits `5`. The HTML viewer is compiled into the CLI binary (`docs/distribution.md`); no development server or repo `schemas/` file is required at runtime.

## What is in the package

| Section | Source | Nested schema |
| --- | --- | --- |
| metadata | product, version, `determinism: byte-stable-v0`, `generatedBy: report --json` | `composelens.report.v0` |
| `source` | discovered files; `services` (one entry per declaration, using service identity `services.<name>`); `serviceSummary` (each unique service once, with every declaration's file, line and column) | (inline) |
| `graph` | `explain --all` provenance graph | `composelens.graph.v0` |
| `check` | CHK01–CHK06 findings, waived state, gate, `assertionExit` | `composelens.check.v0` |
| `diff` | same-selection summary (`empty: true` when both sides match) | `composelens.diff.v0` |
| `differential` | same capture/compare as `composelens differential`: when the Docker CLI is on PATH, `report` runs local `docker compose config` with your project selection (client-side, no daemon; see `SECURITY.md`, `docs/privacy.md`); engine-absent is a typed empty section; `--no-engine` runs no Docker command and a remote include without `--allow-network` skips the capture (engine state `skipped`, `engineSkipReason`) | `composelens.differential.v0` |
| `diagnostics` | catalog entries actually surfaced (for example `exit.assertion` when the check gate would fire) | (inline) |

Invocation-scoped HMAC fingerprints from `inspect` are **omitted** so two generations are byte-identical. Secret values still route through `redact` (including `--redact` / `composelens.redact.yaml`). The fail-closed output guard applies.

`--policy` stays **check-only**. The package uses the default fixed ruleset. Diff-only left/right flags stay invalid on `report`.

## HTML views (`report --html`)

The HTML file inlines CSS (system fonts only) and a renderer. The report JSON sits in `<script type="application/json">` with `json.HTMLEscape` so `</script>` cannot break out. The renderer reads `textContent` and paints with `createElement` + `textContent` only — never `innerHTML` of package strings. There is no `<script src>`, CDN, `@import`, remote font, `fetch`, XHR, or WebSocket. No timestamp is added; the HTML is byte-identical for the same package. The chrome is an offline dashboard: version badge, identity chips, summary tiles, a tab bar, and titled cards. List rows keep identity, type, and state in separate fields (badges), not one concatenated line. It does not load network assets.

Four views share that island:

| View | Data | Interaction |
| --- | --- | --- |
| **Graph** | `graph.nodes` | Move node to node; Enter/Space expands that node's `shadowChain` (winner vs shadowed). Selection identity is `(kind, target)` when those strings collide. |
| **Source** | `source.serviceSummary` (one row per unique service, labelled "declared in FILE:LINE, …"; the Services tile counts unique services), check findings, graph targets | Open a service/field/env chain; from a finding, jump to that target's chain |
| **Diff** | `diff` summary + `differential.rows` | Browse match/divergent/only-side/uncertain rows |
| **Diagnostics** | surfaced catalog diagnostics | Open a row to reach its in-repo `doc` path (text, not a remote link) |

View switching is a tablist (Left/Right). Lists are listboxes (Up/Down). Esc backs out of a detail pane, then to the current tab. Focus uses a 3px `#1d4ed8` outline (≥ 3:1). A skip link (`Skip to report views`) is first in tab order. View switches and selection changes announce through a polite `aria-live` region. Each view has a count-only screen-reader summary. Motion is absent; `@media (prefers-reduced-motion: reduce)` still disables any future animation. Palette contrast is asserted in `TestContrastAA` (WCAG 2.1 AA).

A value containing `<script>`, `</script>`, or `"><img onerror=…>` must appear as **literal text** after JSON.parse of the data island, not as live markup. The file carries a restrictive offline Content-Security-Policy (`default-src 'none'`, no `unsafe-eval`, hash-pinned `script-src` / `style-src`, `base-uri`/`form-action`/`object-src`/`frame-ancestors` locked). Package strings never become `href`/`src`/`on*` sinks; the diagnostic doc path is inert text. Rendered HTML over 4 MiB (`safety.MaxTotalBytes`) fails typed as `input-total-too-large` (exit 3). `frame-ancestors` is included for header-equivalent lock-down; browsers ignore that directive on `<meta>` CSP.

### Keyboard journeys

Land means: open the HTML file. The first control is **Skip to report views**; Tab once more to the Graph tab (`tabindex="0"`). A live headless keyboard walkthrough is not in this toolchain; the sequences below are the contract, and tests assert the tablist/listbox/key-handler/focus-style structure.

**J1 — service source chain**

1. Tab past Skip to report views (or activate it, then Tab) to the Graph tab.
2. Right — Source tab selected.
3. Tab — service list (`#source-list`).
4. Down — next service (if more than one).
5. Enter or Space — `#source-detail` shows that identity's ordered `shadowChain`.
6. Esc — chain closes; focus returns to the service option.

**J2 — finding to source chain**

1. Tab to the Graph tab.
2. Right — Source tab.
3. Tab — service list, then Tab — findings list (`#findings-list`).
4. Down — a finding.
5. Enter or Space — opens the source chain of the finding's `graphNode` (the one provenance-graph node the finding refers to, set by `report` for every finding; an environment field such as `services.web.environment.REQUIRED` refers to the `web:REQUIRED` env node, a missing include to its `include` node) in `#source-detail`. The live region says "Source chain shown" only when a node was found; otherwise "No source chain for this item".
6. Esc — chain closes.

**J3 — provenance graph**

1. Tab to the Graph tab.
2. Tab — node list (`#graph-list`).
3. Down — next node.
4. Enter or Space — expands that node's shadow-chain in `#graph-detail` (winner vs shadowed roles).
5. Esc — collapses the chain.

**J4 — diagnostic doc reference**

1. Tab to the Graph tab.
2. Right, Right, Right — Diagnostics tab.
3. Tab — diagnostics list.
4. Down — a diagnostic.
5. Enter or Space — detail shows `code` / `message` / `remediation` and focuses `#diag-doc` (`doc: …`).
6. Esc — returns to the list.

Home/End jump to the first/last tab or list option. Shift+Tab reverses Tab.

## CLI

```bash
composelens report --json --project-directory <dir>
composelens report --html --project-directory <dir>
composelens report --json --redact <file>
composelens report                 # unsupported: human reserved (exit 5)
composelens report --json --html   # usage (exit 2)
composelens report --json --sarif  # usage (exit 2)
```

`report --json` and `report --html` exit **`0`** when the document is written. Check assertion status is payload, not this command’s exit code. Bound-exceeding or unreadable input exits `3`.

## Schema

Machine-readable JSON Schema: `schemas/composelens.report.v0.json`. The in-repo validator is `internal/report.ValidateBytes`. Unknown top-level fields and missing required fields fail validation. `report --html` does not change that schema.

## Not this command

- GitHub Release signing, cross-builds, or a hosted viewer (`docs/distribution.md` already covers the in-binary HTML viewer)
- A new resolver, new check rules, or a different differential
- Changing inspect / explain / check / differential output
