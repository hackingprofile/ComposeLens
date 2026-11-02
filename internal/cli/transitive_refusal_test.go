// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

// A file below include or extends that the parser or a safety
// bound refuses fails the run with the typed input exit, like a refused root
// file. Intentional absent and cycle states keep working.
func TestRefusedTransitiveFileFailsTheRun(t *testing.T) {
	deep := strings.Repeat("x: {", 70) + "z: 1" + strings.Repeat("}", 70) + "\n"
	bad := map[string]string{
		"malformed": "services: [\n",
		"encoding":  "services: {base: {image: \xff}}",
		"duplicate": "services: {}\nservices: {}\n",
		"depth":     deep,
	}
	for name, body := range bad {
		for _, how := range []string{"include", "extends"} {
			root := "include: bad.yaml\nservices: {web: {image: alpine:3.21}}\n"
			if how == "extends" {
				root = "services: {web: {image: alpine:3.21, extends: {file: bad.yaml, service: base}}}\n"
			}
			dir := writeProbeProject(t, map[string]string{"compose.yaml": root, "bad.yaml": body})
			for _, cmd := range [][]string{{"inspect", "--json"}, {"check", "--json"}, {"explain", "--all", "--json"}, {"report", "--json"}} {
				rt, out, errb := reportRT(dir)
				code := rt.Run(append(append([]string{}, cmd...), "--project-directory", dir))
				if code != exitcode.Input || out.Len() != 0 {
					t.Errorf("%s via %s, %s: code=%d stdout=%d err=%.120s", name, how, cmd[0], code, out.Len(), errb.String())
				}
			}
		}
	}
	// Controls: an absent include and an include cycle are typed states, not failures.
	for name, files := range map[string]map[string]string{
		"absent": {"compose.yaml": "include: missing.yaml\nservices: {web: {image: alpine:3.21}}\n"},
		"cycle":  {"compose.yaml": "include: a.yaml\nservices: {web: {image: alpine:3.21}}\n", "a.yaml": "include: compose.yaml\nservices: {}\n"},
	} {
		dir := writeProbeProject(t, files)
		rt, out, errb := reportRT(dir)
		if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != exitcode.OK || !strings.Contains(out.String(), `"`+name) {
			t.Errorf("control %s: code=%d err=%s", name, code, errb.String())
		}
	}
}
