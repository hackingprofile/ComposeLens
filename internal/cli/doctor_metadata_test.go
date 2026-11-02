// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/engine"
)

// Doctor (JSON and human) and the support bundle never carry
// token-shaped version text or a failing detection's secret detail.
func TestDoctorAndBundleWithholdDetectionMetadata(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a", 30)
	secret := "solar-secretvalue-20261003"
	detectors := map[string]engine.Detector{
		"version-token": {Run: func(context.Context, string, ...string) (string, error) { return tok + "\n", nil }},
		"secret-error": {Run: func(context.Context, string, ...string) (string, error) {
			return "", errors.New("docker config error password=" + secret + " " + tok)
		}, LookPath: func(string) (string, error) { return "found", nil }},
	}
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n"})
	for name, d := range detectors {
		d := d
		for _, args := range [][]string{{"doctor", "--json", "--project-directory", dir}, {"doctor", "--project-directory", dir}} {
			rt, out, errb := reportRT(dir)
			rt.Detect = d.Detect
			rt.Run(args)
			assertNoSecret(t, name+" "+strings.Join(args[:2], " "), tok, out.Bytes(), errb.Bytes())
			assertNoSecret(t, name+" "+strings.Join(args[:2], " "), secret, out.Bytes(), errb.Bytes())
		}
		bundle := filepath.Join(t.TempDir(), "bundle.json")
		rt, out, errb := reportRT(dir)
		rt.Detect = d.Detect
		rt.Run([]string{"doctor", "--bundle", bundle})
		body, _ := os.ReadFile(bundle)
		assertNoSecret(t, name+" bundle", tok, out.Bytes(), errb.Bytes(), body)
		assertNoSecret(t, name+" bundle", secret, out.Bytes(), errb.Bytes(), body)
	}
}
