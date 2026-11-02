// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

// Recognized vendor-token patterns are found anywhere in a string
// (argv, a parent path segment, an OS error), not only in a basename.
func TestStrongTokensFoundAndScrubbedAnywhere(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a", 30)
	for _, s := range []string{
		"--" + tok,
		"--" + tok + "=x",
		`C:\scratch\` + tok + `\normal.yaml`,
		"/tmp/path-" + tok + "/compose.yaml",
		`open C:\missing\` + tok + `.json: The system cannot find the path specified.`,
	} {
		if !ContainsStrongToken(s) {
			t.Errorf("%q: token not recognized", s)
		}
		got := ScrubStrongTokens(s)
		if strings.Contains(got, tok) || !strings.Contains(got, TokenRedacted) {
			t.Errorf("%q: scrubbed to %q", s, got)
		}
	}
	for _, s := range []string{`C:\Users\dev\projects\shop\compose.yaml`, "--project-directory", "ghp_short"} {
		if ContainsStrongToken(s) || ScrubStrongTokens(s) != s {
			t.Errorf("%q: ordinary text changed", s)
		}
	}
}
