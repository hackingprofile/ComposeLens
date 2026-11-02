// SPDX-License-Identifier: Apache-2.0

package engine

import "testing"

func TestParseVersion(t *testing.T) {
	cases := map[string]string{
		"2.29.7\n":                         "2.29.7",
		"Docker Compose version v2.29.7\n": "v2.29.7",
		"docker-compose version 1.29.2\n":  "1.29.2",
		"":                                 "",
	}
	for in, want := range cases {
		if got := parseVersion(in); got != want {
			t.Fatalf("%q: got %q want %q", in, got, want)
		}
	}
}
