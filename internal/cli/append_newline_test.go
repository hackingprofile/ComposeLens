// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestAppendNewlineCopiesWithoutTouchingInput(t *testing.T) {
	raw := make([]byte, 3, 10)
	copy(raw, "abc")
	out := appendNewline(raw)
	if string(out) != "abc\n" {
		t.Fatalf("appendNewline = %q, want %q", out, "abc\n")
	}
	if raw[:4][3] != 0 {
		t.Fatalf("appendNewline wrote into the caller's spare capacity")
	}
	if got := appendNewline([]byte("x\n")); string(got) != "x\n" {
		t.Fatalf("a trailing newline must not be doubled: %q", got)
	}
	if got := appendNewline(nil); len(got) != 0 {
		t.Fatalf("empty input must stay empty: %q", got)
	}
}
