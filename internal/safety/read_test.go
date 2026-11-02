// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestReadAtMostExactAndOverLimit(t *testing.T) {
	dir := t.TempDir()
	exact := filepath.Join(dir, "exact")
	if err := os.WriteFile(exact, []byte("abcd"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := ReadAtMost(exact, 4)
	if err != nil || string(got) != "abcd" {
		t.Fatalf("exact: %q %v", got, err)
	}
	over := filepath.Join(dir, "over")
	if err := os.WriteFile(over, []byte("abcde"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = ReadAtMost(over, 4)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("over: %v", err)
	}
}

func TestReadAtMostMissing(t *testing.T) {
	_, err := ReadAtMost(filepath.Join(t.TempDir(), "nope"), 16)
	if err == nil {
		t.Fatal("expected error")
	}
	if errors.Is(err, ErrInputTooLarge) {
		t.Fatal("missing must not be too-large")
	}
}
