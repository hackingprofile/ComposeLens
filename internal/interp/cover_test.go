// SPDX-License-Identifier: Apache-2.0

package interp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/redact"
)

func TestInterpolateTreeAndResolveScalars(t *testing.T) {
	lookup := g("FOO", "bar")
	raw := []byte("services:\n  web:\n    image: ${FOO}\n    replicas: 2\n")
	d, err := composeparse.Parse(discover.File{Path: "c.yaml", Bytes: raw, Origin: "t"})
	if err != nil {
		t.Fatal(err)
	}
	InterpolateTree(d.Root, lookup)
	scalars := composeparse.StringScalars(d)
	found := false
	for _, s := range scalars {
		if s.Value == "bar" {
			found = true
		}
		if strings.Contains(s.Value, "${FOO}") {
			t.Fatalf("uninterpolated %q", s.Value)
		}
	}
	if !found {
		t.Fatal("missing bar")
	}
	InterpolateTree(nil, lookup)
	vals := ResolveScalars(composeparse.StringScalars(mustParse(t, "image: $FOO\n")), lookup, nil)
	if len(vals) == 0 || vals[0].Resolved != "bar" {
		t.Fatalf("%+v", vals)
	}
}

func mustParse(t *testing.T, raw string) *composeparse.Document {
	t.Helper()
	d, err := composeparse.Parse(discover.File{Path: "c.yaml", Bytes: []byte(raw), Origin: "t"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestTablePathsAndSecretFragments(t *testing.T) {
	if (*Table)(nil).Paths() != nil {
		t.Fatal("nil table")
	}
	dir := t.TempDir()
	env := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(env, []byte("COLOR=blue\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	tab, err := Load(dir, []string{env}, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
	}
	if len(tab.Paths()) != 1 || !strings.Contains(tab.Paths()[0], "extra.env") {
		t.Fatalf("%v", tab.Paths())
	}
	secret := Substitute("${TOKEN}", g("TOKEN", "demo-inline-secret-value"))
	secret.Secret = true
	secret.Raw = "demo-inline-secret-value"
	frags := SecretFragments([]Value{secret, {Secret: false, Resolved: "x"}})
	for _, f := range frags {
		if f == "" {
			t.Fatal("empty frag")
		}
	}
}

func TestInterpolateTreeSkipsNonString(t *testing.T) {
	n := &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!int", Value: "${FOO}"}
	InterpolateTree(n, g("FOO", "1"))
	if n.Value != "${FOO}" {
		t.Fatalf("%q", n.Value)
	}
}
