// SPDX-License-Identifier: Apache-2.0

package report

import (
	"strings"
	"testing"
)

func TestValidateBytesRejects(t *testing.T) {
	if err := ValidateBytes([]byte("not-json")); err == nil {
		t.Fatal("garbage")
	}
	if err := ValidateBytes([]byte(`{"schema":"nope"}`)); err == nil {
		t.Fatal("incomplete")
	}
	raw, err := Encode(Package{Schema: Schema, Determinism: Determinism})
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBytes(raw); err == nil {
		t.Fatal("empty package should fail nested required fields")
	}
}

func TestContrastParseHexErrors(t *testing.T) {
	if _, err := ContrastRatio("not-hex", ColorBg); err == nil {
		t.Fatal("bad fg")
	}
	if _, err := ContrastRatio("#gg0000", ColorBg); err == nil {
		t.Fatal("bad digit")
	}
}

func TestCSPPolicyContainsHashes(t *testing.T) {
	h := cspSHA256([]byte("abc"))
	if !strings.HasPrefix(h, "sha256-") {
		t.Fatal(h)
	}
	p := cspPolicy(h, h, h)
	if !strings.Contains(p, "default-src 'none'") || !strings.Contains(p, h) {
		t.Fatal(p)
	}
}

func TestAssembleEmptyAndEncode(t *testing.T) {
	pkg := Assemble(Input{})
	if pkg.Source.FileEvidence == "" {
		t.Fatal("file evidence")
	}
	raw, err := Encode(pkg)
	if err != nil {
		t.Fatal(err)
	}
	_ = ValidateBytes(raw)
}
