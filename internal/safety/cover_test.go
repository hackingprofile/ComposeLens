// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBudgetMonotoneAndOptional(t *testing.T) {
	if Optional(nil) != nil {
		t.Fatal("empty optional")
	}
	b := NewBudget()
	if b.Bytes() != 0 || b.Files() != 0 {
		t.Fatal("zero")
	}
	if err := b.ChargePath("a.yaml", 10); err != nil {
		t.Fatal(err)
	}
	if b.Bytes() != 10 || b.Files() != 1 {
		t.Fatalf("after first %d %d", b.Bytes(), b.Files())
	}
	if err := b.ChargePath("a.yaml", 10); err != nil {
		t.Fatal(err)
	}
	if b.Bytes() != 10 || b.Files() != 1 {
		t.Fatal("duplicate path must not increase")
	}
	if err := b.ChargePath("b.yaml", 20); err != nil {
		t.Fatal(err)
	}
	if b.Bytes() != 30 || b.Files() != 2 {
		t.Fatalf("after second %d %d", b.Bytes(), b.Files())
	}
	if (*Budget)(nil).Bytes() != 0 || (*Budget)(nil).Files() != 0 {
		t.Fatal("nil budget")
	}
}

func TestGuardMessageAndCaseFold(t *testing.T) {
	if err := GuardMessage("ok output here", []string{"super-secret-token-value"}); err != nil {
		t.Fatal(err)
	}
	if err := GuardMessage("leaks SUPER-SECRET-TOKEN-VALUE here", []string{"super-secret-token-value"}); err == nil {
		t.Fatal("case-fold leak")
	}
}

func TestIsResourceBoundAndCodeOf(t *testing.T) {
	if IsResourceBound(nil) || CodeOf(nil) != "" {
		t.Fatal("nil")
	}
	err := NewParseError(CodeFileTooLarge, "f.yaml", "too big")
	if !IsResourceBound(err) || CodeOf(err) != CodeFileTooLarge {
		t.Fatal(err)
	}
	if IsResourceBound(NewParseError(CodeMalformed, "f.yaml", "nope")) {
		t.Fatal("malformed is not a resource bound")
	}
}

func TestReadChargedAndLimited(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "ok.yaml")
	if err := os.WriteFile(p, []byte("services: {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBudget()
	raw, err := ReadCharged(b, p, 64)
	if err != nil || string(raw) != "services: {}\n" {
		t.Fatalf("%q %v", raw, err)
	}
	if _, err := ReadAtMost(p, 4); err == nil {
		t.Fatal("want too large")
	}
	if _, err := ReadAtMostFrom(bytes.NewReader([]byte("abc")), 2); err == nil {
		t.Fatal("want too large from")
	}
	got, err := ReadAtMostFrom(bytes.NewReader([]byte("ab")), 2)
	if err != nil || string(got) != "ab" {
		t.Fatalf("%q %v", got, err)
	}
	bb := &BoundBuffer{Max: 4}
	_, _ = bb.Write([]byte("abcdef"))
	if !bb.Overflow() || bb.Len() != 4 || bb.String() != "abcd" {
		t.Fatalf("%q overflow=%v", bb.String(), bb.Overflow())
	}
	_ = bb.Bytes()
}

func TestParseErrorEmptyPathAndSecretPath(t *testing.T) {
	e := NewParseError(CodeTotalTooLarge, "", "total input exceeds")
	if !strings.Contains(e.Error(), "total input exceeds") {
		t.Fatal(e.Error())
	}
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	red := NewParseError(CodeFileTooLarge, probe, probe)
	if strings.Contains(red.Error(), probe) {
		t.Fatal(red.Error())
	}
}
