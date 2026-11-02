// SPDX-License-Identifier: Apache-2.0

package envfile

import "testing"

func TestUnicodeEscapes(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{`café`, "café"},
		{`€5`, "€5"},
		{`￿`, "￿"},
		{`\uD800x`, `\uD800x`}, // a lone surrogate is not a rune: kept as written
		{`\u00`, `\u00`},       // too short: kept as written
		{`\uzzzz`, `\uzzzz`},   // not hex: kept as written
	} {
		if got := expandEscapes(tc.in); got != tc.want {
			t.Errorf("expandEscapes(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
