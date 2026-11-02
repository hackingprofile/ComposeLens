// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestEscapeControlsShowsInvisibleCharacters(t *testing.T) {
	cases := map[string]string{
		"plain text":          "plain text",
		"a\nb\rc\td":          `a\nb\rc\td`,
		"b\u009b31m":          `b\x9b31m`,
		"x\u202eevil":         `x\u202eevil`,
		"zero\u200bwidth":     `zero\u200bwidth`,
		"sep\u2028line":       `sep\u2028line`,
		"bom\ufeff":           `bom\ufeff`,
		"bad\xffbyte":         `bad\xffbyte`,
		"ünïcødé stays":       "ünïcødé stays",
		"line1\n::error::x":   `line1\n::error::x`,
		"del\x7f and \x1b[0m": `del\x7f and \x1b[0m`,
	}
	for in, want := range cases {
		if got := EscapeControls(in); got != want {
			t.Errorf("EscapeControls(%q) = %q, want %q", in, got, want)
		}
	}
	if got := EscapeInvisibles("keep\nnewlines\tand tabs \u202e"); got != "keep\nnewlines\tand tabs "+`\u202e` {
		t.Errorf("EscapeInvisibles = %q", got)
	}
}
