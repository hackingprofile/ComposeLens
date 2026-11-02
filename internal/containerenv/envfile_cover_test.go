// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/safety"
)

func TestQuotedEnvFileUnescape(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "q.env")
	body := "FOO=\"a\\nb\"\nBAZ=plain # comment\nexport Q=1\n# skip\n\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := readEnvFile(p, "", nil, safety.NewBudget())
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, e := range got {
		m[e.Key] = e.Value
	}
	if m["FOO"] != "a\nb" {
		t.Fatalf("FOO=%q", m["FOO"])
	}
	if m["BAZ"] != "plain" {
		t.Fatalf("BAZ=%q", m["BAZ"])
	}
	if m["Q"] != "1" {
		t.Fatalf("Q=%q", m["Q"])
	}
}

func TestUnquoteEnvEdges(t *testing.T) {
	if _, ok := unquoteEnv("x"); ok {
		t.Fatal("short")
	}
	if _, ok := unquoteEnv("abc"); ok {
		t.Fatal("unquoted")
	}
	s, ok := unquoteEnv(`"hello"`)
	if !ok || s != "hello" {
		t.Fatalf("%q %v", s, ok)
	}
	if _, ok := unquoteEnv(`"unterminated`); ok {
		t.Fatal("open")
	}
}
