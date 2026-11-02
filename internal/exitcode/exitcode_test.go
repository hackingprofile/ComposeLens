// SPDX-License-Identifier: Apache-2.0

package exitcode

import "testing"

func TestTaxonomyStable(t *testing.T) {
	want := map[string]int{
		"OK": 0, "Internal": 1, "Usage": 2, "Input": 3, "Safety": 4, "Unsupported": 5, "Assertion": 6,
	}
	got := map[string]int{
		"OK": OK, "Internal": Internal, "Usage": Usage, "Input": Input, "Safety": Safety, "Unsupported": Unsupported, "Assertion": Assertion,
	}
	for k, v := range want {
		if got[k] != v {
			t.Fatalf("%s=%d want %d", k, got[k], v)
		}
	}
	seen := map[int]string{}
	for name, code := range got {
		if prev, ok := seen[code]; ok {
			t.Fatalf("collision %d %s %s", code, prev, name)
		}
		seen[code] = name
	}
}
