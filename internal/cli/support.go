// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"

	"composelens/internal/engine"
	"composelens/internal/enginecap"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/paths"
	"composelens/internal/redact"
	"composelens/internal/safety"
	"composelens/internal/version"
)

const (
	supportBundleSchema = "composelens.support.bundle.v0"
	supportDisclaimer   = "environment and diagnostic metadata only — no project source values, no secrets, no telemetry"
	supportTelemetry    = "none — nothing is sent anywhere"
)

// CrashGuidance is the telemetry-free stderr block appended on exit 1.
func CrashGuidance() string {
	return "" +
		"ComposeLens did not send this failure anywhere (no telemetry, no crash reporter, no network upload).\n" +
		"File a bug with .github/ISSUE_TEMPLATE/bug.yml. Attach a diagnostic bundle. Never paste secrets or Compose file contents.\n" +
		"Generate a bundle: composelens doctor --bundle composelens-support.json\n" +
		"See docs/support.md.\n"
}

func writeCrashGuidance(w io.Writer) {
	msg := CrashGuidance()
	if err := safety.Guard([]byte(msg), nil); err != nil {
		return
	}
	writeErr(w, "%s", msg)
}

// RecoveredPanic maps a top-level panic to exit 1 without printing the panic value.
func RecoveredPanic(stderr io.Writer, _ any) int {
	msg := "composelens: internal error (a panic was recovered; the panic value is not printed)\n" + CrashGuidance()
	if err := safety.Guard([]byte(msg), nil); err != nil {
		writeErr(stderr, "composelens: refuse to write output: fail-closed (%s)\n", err.Error())
		return exitcode.Safety
	}
	writeErr(stderr, "%s", msg)
	return exitcode.Internal
}

type supportBundle struct {
	Schema             string           `json:"schema"`
	Product            string           `json:"product"`
	Version            string           `json:"version"`
	Disclaimer         string           `json:"disclaimer"`
	Telemetry          string           `json:"telemetry"`
	Platform           PlatformInfo     `json:"platform"`
	Engine             engine.Info      `json:"engine"`
	EngineCapabilities enginecap.Report `json:"engineCapabilities"`
	Features           FeatureInfo      `json:"features"`
	Evidence           string           `json:"evidence"`
}

func (rt Runtime) writeSupportBundle(opt Options) int {
	detect := rt.Detect
	if detect == nil {
		detect = engine.Detect
	}
	eng := detect()
	if eng.Err != nil {
		return rt.fail(opt, exitcode.Input, eng.Err, eng.GuardMaterial())
	}
	doc := supportBundle{
		Schema:             supportBundleSchema,
		Product:            version.Name,
		Version:            version.Version,
		Disclaimer:         supportDisclaimer,
		Telemetry:          supportTelemetry,
		Platform:           platformInfo(),
		Engine:             eng,
		EngineCapabilities: enginecap.FromDetect(eng.State, eng.Version),
		Features: FeatureInfo{
			Implemented: implementedFeatures,
			Deferred:    deferredFeatures,
		},
		Evidence: evidence.Known,
	}
	raw, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		writeErr(rt.Stderr, "composelens: encode: %v\n", err)
		return exitcode.Internal
	}
	raw = append(raw, '\n')
	// The bundle carries detection metadata only; it is guarded against the
	// values withheld from that metadata (and, in Guard, recognized tokens).
	if err := safety.Guard(raw, eng.GuardMaterial()); err != nil {
		writeErr(rt.Stderr, "composelens: refuse to write output: fail-closed (%s)\n", err.Error())
		return exitcode.Safety
	}
	resolved, err := paths.Resolve(rt.Cwd, opt.Bundle)
	if err != nil {
		return rt.fail(opt, exitcode.Input, redact.RedactInError(err, opt.Bundle), nil)
	}
	// A new file only: O_EXCL refuses an existing file and any symlink at the
	// path, so the bundle never replaces a project file or writes through a
	// link.
	f, err := os.OpenFile(resolved, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if errors.Is(err, fs.ErrExist) {
			return rt.fail(opt, exitcode.Input, safety.NewParseError(safety.CodeOutputExists, resolved, "the bundle path already exists; it is not overwritten"), nil)
		}
		writeErr(rt.Stderr, "composelens: write: %v\n", redact.RedactInError(err, opt.Bundle))
		return exitcode.Internal
	}
	_, werr := f.Write(raw)
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		writeErr(rt.Stderr, "composelens: write: %v\n", werr)
		return exitcode.Internal
	}
	return exitcode.OK
}
