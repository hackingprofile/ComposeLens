// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

func TestParseAddAndAllowlist(t *testing.T) {
	t.Cleanup(Reset)
	cfg, err := Parse([]byte(`
schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"
allowKeys:
  - PUBLIC_TOKEN
allowValues:
  - license-spdx-mit
`))
	if err != nil {
		t.Fatal(err)
	}
	Use(cfg)
	custom := "clx_" + strings.Repeat("a", 24)
	if !IsSecretKey("X_INTERNAL_ID") {
		t.Fatal("added key not secret")
	}
	if !LooksLikeSecret(custom) {
		t.Fatal("added value pattern not secret")
	}
	if IsSecretKey("PUBLIC_TOKEN") {
		t.Fatal("allowlisted key still secret")
	}
	if LooksLikeSecret("license-spdx-mit") {
		t.Fatal("allowlisted value still secret")
	}
	if !MustRedact("API_TOKEN", "keyed-secret-value") {
		t.Fatal("real secret key must stay redacted")
	}
	if !LooksLikeSecret("aB3$xY9#mK2pQ7nx5wR8tV1cZ4jH6uD0") {
		t.Fatal("neighbor high-entropy must stay redacted")
	}
}

func TestDefaultUnchangedWithoutConfig(t *testing.T) {
	Reset()
	if IsSecretKey("X_INTERNAL_ID") {
		t.Fatal("default must not treat X_INTERNAL_ID as secret")
	}
	custom := "clx_" + strings.Repeat("a", 24)
	if LooksLikeSecret(custom) {
		t.Fatal("default must not treat custom prefix as secret")
	}
	if !IsSecretKey("API_TOKEN") || !LooksLikeSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("defaults weakened")
	}
}

func TestUnknownFieldRejected(t *testing.T) {
	_, err := Parse([]byte("schema: composelens.redact.v0\ndisable: true\n"))
	if err == nil {
		t.Fatal("expected unknown field")
	}
	pe, ok := err.(*Error)
	if !ok || pe.Kind != KindUnknownField {
		t.Fatalf("kind=%v", err)
	}
}

func TestBlanketAllowRejected(t *testing.T) {
	_, err := Parse([]byte("schema: composelens.redact.v0\nallowValues:\n  - \".*\"\n"))
	if err == nil || !strings.Contains(err.Error(), "specific") {
		t.Fatalf("blanket allow: %v", err)
	}
	_, err = Parse([]byte("schema: composelens.redact.v0\nsecretValues:\n  - \".*\"\n"))
	if err == nil || !strings.Contains(err.Error(), "blanket") {
		t.Fatalf("blanket pattern: %v", err)
	}
}

func TestSecretShapedPatternNotEchoed(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	_, err := Parse([]byte("schema: composelens.redact.v0\nsecretValues:\n  - " + probe + "\n"))
	if err == nil {
		t.Fatal("expected secret-shaped rejection")
	}
	if strings.Contains(err.Error(), probe) {
		t.Fatalf("diagnostic leaked probe: %v", err)
	}
	if !strings.Contains(err.Error(), "not a secret-shaped value") && !strings.Contains(err.Error(), "pattern or name") {
		t.Fatalf("err=%v", err)
	}
}

func TestDisplayTokenIrreversible(t *testing.T) {
	t.Cleanup(Reset)
	a, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	raw := "site-id-0001"
	ta := a.Token(raw)
	tb := b.Token(raw)
	if ta == raw || tb == raw || ta == tb {
		t.Fatalf("reversible or linked tokens %s %s", ta, tb)
	}
	if !strings.HasPrefix(ta, "hmac-sha256:") {
		t.Fatalf("default token %s", ta)
	}
	for _, g := range a.GuardMaterial() {
		if g != "" && strings.Contains(ta, g) {
			t.Fatal("key material in token")
		}
	}
	cfg, err := Parse([]byte("schema: composelens.redact.v0\ndisplay: redacted\n"))
	if err != nil {
		t.Fatal(err)
	}
	Use(cfg)
	if a.Token(raw) != TokenRedacted {
		t.Fatalf("display redacted=%s", a.Token(raw))
	}
	if a.Token(raw) == raw {
		t.Fatal("placeholder must not equal raw")
	}
}

func TestEmptyConfigRejected(t *testing.T) {
	_, err := Parse([]byte("   \n"))
	if err == nil {
		t.Fatal("expected empty")
	}
	pe, ok := err.(*Error)
	if !ok || pe.Kind != KindMalformed {
		t.Fatalf("err=%v", err)
	}
}
