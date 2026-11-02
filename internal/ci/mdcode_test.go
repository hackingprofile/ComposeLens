// SPDX-License-Identifier: Apache-2.0

package ci

import "testing"

func TestMdCodeCannotBeClosedByItsContent(t *testing.T) {
	cases := map[string]string{
		"plain":            "`plain`",
		"a` [x](y) `b":     "``a` [x](y) `b``",
		"``two``":          "``` ``two`` ```",
		"`edge":            "`` `edge ``",
		"line1\n::error::": "`line1" + `\n` + "::error::`",
	}
	for in, want := range cases {
		if got := mdCode(in); got != want {
			t.Errorf("mdCode(%q) = %q, want %q", in, got, want)
		}
	}
}
