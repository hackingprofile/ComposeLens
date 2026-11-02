// SPDX-License-Identifier: Apache-2.0

package interp

import (
	"strings"
	"testing"

	"composelens/internal/redact"
)

func FuzzSubstituteDoesNotPanicOrEmitSecret(f *testing.F) {
	f.Add("${FOO:-bar}")
	f.Add("$$")
	f.Add("${MUST:?no}")
	f.Add("$TOKEN")
	f.Add("")
	lookup := g("FOO", "ok", "TOKEN", "demo-not-a-github-token")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic: %v", rec)
			}
		}()
		v := Substitute(raw, lookup)
		if redact.LooksLikeSecret(v.Resolved) && strings.Contains(v.Resolved, "ghp_") {
			t.Fatal("github-token-shaped output")
		}
	})
}
