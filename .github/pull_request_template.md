## Summary

<!-- What changed, and why. -->

## Contract impact

- [ ] No public CLI / JSON / exit-code change
- [ ] Public contract change documented in `CHANGELOG.md` and `docs/cli.md`

## Secret safety

- [ ] No raw secrets in code, fixtures, snapshots, logs, or this PR body
- [ ] New output paths still pass the fail-closed redaction guard

## Evidence

Commands run locally (paste redacted output or attach files):

```text
go test ./...
```

Platform:

## Out of scope check

- [ ] Normalization claims match `docs/normalize.md` (shell vs exec stay distinct; not an engine differential)
- [ ] Fixture taxonomy claims match `docs/fixtures.md` (index in place; corpus pins in `docs/corpus.md`; not a CLI command)
- [ ] Engine adapter claims match `docs/engineadapter.md` (typed capture only; not a differential; no Docker install)
- [ ] Engine capability claims match `docs/enginecap.md` (v2 window; unverified behaviors unknown; not a differential)
- [ ] This PR does not claim engine parity; differential rows match `docs/differential.md`
- [ ] Interpolation claims match `docs/interpolation.md` (recursive interpolation remains deferred unless implemented and proven)
- [ ] Merge claims match `docs/merge.md` (sequence append / unique-key dedup / atomic replace; unverified sequence fields stay `unknown`)
- [ ] Profile claims match `docs/profiles.md`
- [ ] Include claims match `docs/include.md` (long-form `env_file`/`project_directory` remain unapplied unless implemented and proven)
- [ ] Extends claims match `docs/extends.md` (string short form remains unsupported unless implemented and proven)
- [ ] Container-environment claims match `docs/containerenv.md` (Dockerfile `ENV` and `run -e` remain unapplied unless implemented and proven)
- [ ] Explain claims match `docs/explain.md` (composition of existing stages)
- [ ] Graph claims match `docs/graph.md` (aggregation of existing stages; not a new resolver)
- [ ] Diff claims match `docs/diff.md` (same-file selections; not an engine differential)
- [ ] Check claims match `docs/check.md` (fixed ruleset; local SARIF only; not a policy engine; not an upload)
- [ ] This PR does not claim GitHub Actions matrix results unless those jobs actually ran
