// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A recognized token in argv, a path operand, a write path or the
// project directory is never echoed in diagnostics or output.
func TestRecognizedTokensNeverEchoed(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a", 30)
	base := t.TempDir()
	proj := filepath.Join(base, "path-"+tok)
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(proj, "compose.yaml"), []byte("services: {web: {image: alpine:3.21}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	inline := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n      PASSWORD: solar-secretvalue\n"})
	cases := [][]string{
		{"--" + tok},
		{"--" + tok + "=x", "version"},
		{"version", filepath.Join(base, tok, "normal.yaml")},
		{"doctor", "--bundle", filepath.Join(base, "missing", tok+".json")},
		{"inspect", "--json", "--project-directory", proj},
		{"explain", "--all", "--json", "--project-directory", proj},
		{"report", "--json", "--project-directory", proj},
		{"doctor", "--json", "--project-directory", proj},
		{"inspect", "--json", "--project-directory", filepath.Join(base, "absent-"+tok)},
		{"inspect", "--json", "-f", filepath.Join(base, "absent-"+tok, "compose.yaml")},
	}
	for _, args := range cases {
		rt, out, errb := reportRT(base)
		rt.Run(args)
		assertNoSecret(t, strings.Join(args, " "), tok, out.Bytes(), errb.Bytes())
	}
	t.Setenv("COMPOSELENS_JSON_PATH", filepath.Join(base, "missing", tok+".json"))
	rt, out, errb := reportRT(base)
	rt.Run([]string{"check", "--github", "--project-directory", inline})
	assertNoSecret(t, "COMPOSELENS_JSON_PATH write error", tok, out.Bytes(), errb.Bytes())
}
