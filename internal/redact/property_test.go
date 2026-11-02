// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
)

func TestDisplayForSecretAndJSONConfig(t *testing.T) {
	t.Cleanup(Reset)
	if DisplayForSecret("hmac-sha256:abcd", false) != "hmac-sha256:abcd" {
		t.Fatal("non-secret")
	}
	cfg, err := Parse([]byte(`{"schema":"composelens.redact.v0","display":"redacted"}`))
	if err != nil {
		t.Fatal(err)
	}
	restore := Use(cfg)
	defer restore()
	if DisplayForSecret("hmac-sha256:abcd", true) != TokenRedacted {
		t.Fatal("redacted overlay")
	}
}

func TestConfigSecretFragmentsFromJSON(t *testing.T) {
	if ConfigSecretFragments(nil) != nil {
		t.Fatal("empty")
	}
	raw := []byte(`{"schema":"composelens.redact.v0","allowValues":["license-spdx-mit"]}`)
	_ = ConfigSecretFragments(raw)
	_ = ConfigSecretFragments([]byte("{not-json"))
	_ = ConfigSecretFragments([]byte("x: y\n"))
}

func TestPropertyFingerprintNeverEmitsSecret(t *testing.T) {
	fp, err := NewFingerprinterFrom(bytes.NewReader(bytes32('k')))
	if err != nil {
		t.Fatal(err)
	}
	cfg := &quick.Config{MaxCount: 200, Rand: rand.New(rand.NewSource(51))}
	fn := func(s string) bool {
		if s == "" {
			return true
		}
		tok := fp.Fingerprint(s)
		if tok == s {
			return false
		}
		if len(s) >= 6 && strings.Contains(tok, s) {
			return false
		}
		return strings.HasPrefix(tok, "hmac-sha256:")
	}
	if err := quick.Check(fn, cfg); err != nil {
		t.Fatal(err)
	}
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	tok := fp.Fingerprint(probe)
	if strings.Contains(tok, probe) || tok == probe {
		t.Fatal("secret emitted")
	}
}

func bytes32(b byte) []byte {
	out := make([]byte, 32)
	for i := range out {
		out[i] = b
	}
	return out
}
