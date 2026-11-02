// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/engine"
	"composelens/internal/exitcode"
	"composelens/internal/safety"
)

// An engine-output overflow during detection refuses doctor and the
// support bundle with the typed input exit (3), like the config adapter.
func TestDoctorRefusesOversizedDetectionOutput(t *testing.T) {
	d := engine.Detector{Run: func(context.Context, string, ...string) (string, error) {
		return "", safety.NewParseError(safety.CodeEngineOutputTooLarge, "", "engine output exceeds declared bound")
	}}
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n"})
	for _, args := range [][]string{{"doctor", "--json", "--project-directory", dir}, {"doctor", "--project-directory", dir}} {
		rt, out, errb := reportRT(dir)
		rt.Detect = d.Detect
		if code := rt.Run(args); code != exitcode.Input || out.Len() != 0 {
			t.Errorf("%v: code=%d stdout=%d err=%s", args, code, out.Len(), errb.String())
		}
	}
	bundle := filepath.Join(t.TempDir(), "bundle.json")
	rt, _, errb := reportRT(dir)
	rt.Detect = d.Detect
	if code := rt.Run([]string{"doctor", "--bundle", bundle}); code != exitcode.Input {
		t.Errorf("bundle code=%d err=%s", code, errb.String())
	}
	if _, err := os.Stat(bundle); err == nil {
		t.Error("bundle written despite the overflow")
	}
}
