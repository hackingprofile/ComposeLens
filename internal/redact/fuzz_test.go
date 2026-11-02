// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"testing"
	"unicode/utf8"
)

func FuzzParseDoesNotPanic(f *testing.F) {
	f.Add([]byte("schema: composelens.redact.v0\n"))
	f.Add([]byte(`{"schema":"composelens.redact.v0"}`))
	f.Add([]byte("{"))
	f.Add([]byte{0xff})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32*1024 {
			raw = raw[:32*1024]
		}
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic: %v", rec)
			}
		}()
		_, err := Parse(raw)
		if err != nil && !utf8.Valid(raw) && err.Error() == "" {
			t.Fatal("empty error")
		}
	})
}
