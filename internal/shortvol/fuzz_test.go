// SPDX-License-Identifier: Apache-2.0

package shortvol

import "testing"

func FuzzParseDoesNotPanic(f *testing.F) {
	f.Add("C:\\data:/data:ro")
	f.Add("/data")
	f.Add("src:dst:rw")
	f.Add("")
	f.Add("{")
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic: %v", rec)
			}
		}()
		_, _ = Parse(raw)
		_ = Target(raw)
		_ = WindowsDrive(raw)
	})
}
