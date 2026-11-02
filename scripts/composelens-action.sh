#!/usr/bin/env bash
# ComposeLens composite-action wrapper.
# Builds the CLI from THIS source tree (no release download).
# Secret-safe: does not echo env, does not print Compose values, routes
# check output through composelens (redaction + safety.Guard).
set -eu

truthy() {
  case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in
    true|yes|1) return 0 ;;
    *) return 1 ;;
  esac
}

ROOT="${COMPOSELENS_ACTION_PATH:-${GITHUB_ACTION_PATH:-}}"
if [ -z "$ROOT" ]; then
  printf '%s\n' "composelens action: missing COMPOSELENS_ACTION_PATH / GITHUB_ACTION_PATH" >&2
  exit 1
fi
if [ ! -f "$ROOT/go.mod" ] || [ ! -d "$ROOT/cmd/composelens" ]; then
  printf '%s\n' "composelens action: action path is not a ComposeLens source tree" >&2
  exit 1
fi

FAIL_ON="$(printf '%s' "${INPUT_FAIL_ON:-error}" | tr '[:upper:]' '[:lower:]')"
case "$FAIL_ON" in
  error|warning|info|never) ;;
  *)
    printf '%s\n' "composelens action: fail-on must be error, warning, info, or never" >&2
    exit 2
    ;;
esac

OUTDIR="${RUNNER_TEMP:-${TMPDIR:-${TEMP:-/tmp}}}"
mkdir -p "$OUTDIR"

EXE="composelens"
case "${RUNNER_OS:-}" in
  Windows) EXE="composelens.exe" ;;
esac
if [ "$EXE" = "composelens" ]; then
  case "$(uname -s 2>/dev/null || printf '%s' unknown)" in
    MINGW*|MSYS*|CYGWIN*) EXE="composelens.exe" ;;
  esac
fi
BIN="$OUTDIR/$EXE"

# Build from source. A GitHub-hosted runner may fetch modules (gopkg.in/yaml.v3)
# unless the module cache is already populated. GOPROXY is not forced off here.
# A local GOPROXY=off run uses an existing module cache. Never curl a release.
(
  cd "$ROOT"
  go build -o "$BIN" ./cmd/composelens
)

PROJECT="${INPUT_PROJECT_DIRECTORY:-.}"
JSON_PATH=""
SARIF_PATH=""
SUMMARY_PATH=""
# A disabled output is cleared from the child's environment, so a path inherited from the job
# cannot reach the CLI. The CLI appends to GITHUB_STEP_SUMMARY whenever it is set (the direct
# `check --github` behaviour), so emit-summary=false clears that too, for this step's child only.
if truthy "${INPUT_EMIT_JSON:-true}"; then
  JSON_PATH="$OUTDIR/composelens-check.json"
  export COMPOSELENS_JSON_PATH="$JSON_PATH"
else
  unset COMPOSELENS_JSON_PATH
fi
if truthy "${INPUT_EMIT_SARIF:-true}"; then
  SARIF_PATH="$OUTDIR/composelens-check.sarif"
  export COMPOSELENS_SARIF_PATH="$SARIF_PATH"
else
  unset COMPOSELENS_SARIF_PATH
fi
if truthy "${INPUT_EMIT_SUMMARY:-true}"; then
  SUMMARY_PATH="$OUTDIR/composelens-check.md"
  export COMPOSELENS_GITHUB_SUMMARY="$SUMMARY_PATH"
else
  unset COMPOSELENS_GITHUB_SUMMARY GITHUB_STEP_SUMMARY
fi
export COMPOSELENS_FAIL_ON="$FAIL_ON"

set -- "$BIN" check --github --project-directory "$PROJECT"

split_list() {
  printf '%s' "${1:-}" | tr ',;\r' '\n' | while IFS= read -r item || [ -n "$item" ]; do
    item="${item#"${item%%[![:space:]]*}"}"
    item="${item%"${item##*[![:space:]]}"}"
    [ -n "$item" ] || continue
    printf '%s\n' "$item"
  done
}

while IFS= read -r f || [ -n "${f:-}" ]; do
  [ -n "$f" ] || continue
  set -- "$@" --file "$f"
done <<EOF
$(split_list "${INPUT_FILES:-}")
EOF

while IFS= read -r p || [ -n "${p:-}" ]; do
  [ -n "$p" ] || continue
  set -- "$@" --profile "$p"
done <<EOF
$(split_list "${INPUT_PROFILES:-}")
EOF

if [ -n "${INPUT_POLICY:-}" ]; then
  set -- "$@" --policy "$INPUT_POLICY"
fi
if [ -n "${INPUT_REDACT:-}" ]; then
  set -- "$@" --redact "$INPUT_REDACT"
fi

ANN_OUT="$OUTDIR/composelens-annotations.txt"
CODE=0
if truthy "${INPUT_EMIT_ANNOTATIONS:-true}"; then
  "$@" || CODE=$?
else
  "$@" >"$ANN_OUT" || CODE=$?
fi

if [ -n "${GITHUB_OUTPUT:-}" ]; then
  {
    printf 'json-path=%s\n' "$JSON_PATH"
    printf 'sarif-path=%s\n' "$SARIF_PATH"
    printf 'summary-path=%s\n' "$SUMMARY_PATH"
    printf 'exit-code=%s\n' "$CODE"
  } >>"$GITHUB_OUTPUT"
fi

exit "$CODE"
