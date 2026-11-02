// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"composelens/internal/exitcode"
)

// A collected secret copied into an innocent key must not leak
// through any serialized format once JSON or HTML escaping has changed its
// bytes. Each format either withholds it or refuses (exit 4).
func TestSerializedDuplicateSecretNeverLeaks(t *testing.T) {
	cases := map[string]struct{ yaml, secret string }{
		"quote":     {`solar-\"quoted\"-value`, `solar-"quoted"-value`},
		"newline":   {`solar-first\nsecond`, "solar-first\nsecond"},
		"backslash": {`solar-back\value`, `solar-back\value`},
		"html":      {`solar-<redacted>-value&amp`, `solar-<redacted>-value&amp`},
		"separator": {`solar-line value`, "solar-line value"},
	}
	modes := [][]string{
		{"inspect", "--json"},
		{"explain", "web:COPY", "--json"},
		{"explain", "--all", "--json"},
		{"report", "--json"},
		{"report", "--html"},
		{"inspect"},
		{"explain", "web:COPY"},
	}
	for name, c := range cases {
		dir := writeProbeProject(t, map[string]string{
			"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n      PASSWORD: \"" + c.yaml + "\"\n      COPY: \"" + c.yaml + "\"\n",
		})
		for _, m := range modes {
			rt, out, errb := reportRT(dir)
			args := append(append([]string{}, m...), "--project-directory", dir)
			code := rt.Run(args)
			label := name + " " + m[0] + " " + m[len(m)-1]
			if code != exitcode.OK && code != exitcode.Safety {
				t.Errorf("%s: code=%d err=%s", label, code, errb.String())
			}
			assertNoSecret(t, label, c.secret, out.Bytes(), errb.Bytes())
		}
	}
}
