// SPDX-License-Identifier: Apache-2.0

package composeparse

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"composelens/internal/discover"
	"composelens/internal/safety"
	"composelens/internal/testenv"
)

func parseNoPanic(t *testing.T, f discover.File) (doc *Document, err error) {
	t.Helper()
	defer func() {
		if rec := recover(); rec != nil {
			t.Fatalf("panic: %v", rec)
		}
	}()
	return Parse(f)
}

func fileFrom(path string, raw []byte) discover.File {
	return discover.File{Path: path, Bytes: raw, Origin: "test"}
}

func nestedYAML(depth int) []byte {
	var b strings.Builder
	for i := 0; i < depth; i++ {
		b.WriteString(strings.Repeat("  ", i))
		b.WriteString("n:\n")
	}
	b.WriteString(strings.Repeat("  ", depth))
	b.WriteString("k: v\n")
	return []byte(b.String())
}

func aliasBomb(levels int) []byte {
	var b strings.Builder
	b.WriteString("services:\n  web:\n    image: alpine\n")
	b.WriteString("x0: &x0 [a]\n")
	for i := 1; i <= levels; i++ {
		prev := strconv.Itoa(i - 1)
		cur := strconv.Itoa(i)
		b.WriteString("x")
		b.WriteString(cur)
		b.WriteString(": &x")
		b.WriteString(cur)
		b.WriteString(" [*x")
		b.WriteString(prev)
		b.WriteString(", *x")
		b.WriteString(prev)
		b.WriteString("]\n")
	}
	return []byte(b.String())
}

func TestHardeningBattery(t *testing.T) {
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	cases := []struct {
		name string
		raw  []byte
		code safety.Code
	}{
		{name: "deep-nesting", raw: nestedYAML(80), code: safety.CodeTooDeep},
		{name: "alias-bomb", raw: aliasBomb(16), code: safety.CodeAliasLimit},
		{name: "oversized", raw: append([]byte("services:\n  web:\n    image: alpine\n"), bytes.Repeat([]byte("x"), safety.MaxFileBytes)...), code: safety.CodeFileTooLarge},
		{name: "malformed", raw: []byte("services:\n  web:\n    image: [\n"), code: safety.CodeMalformed},
		{name: "bad-encoding", raw: append([]byte("services:\n  web:\n    image: alpine\n"), 0xff, 0xfe, 0x00), code: safety.CodeEncoding},
		{name: "duplicate-key", raw: []byte("services:\n  web:\n    image: alpine\n    image: nginx\n"), code: safety.CodeDuplicateKey},
		{name: "not-mapping", raw: []byte("- not\n- a\n- mapping\n"), code: safety.CodeNotMapping},
		{name: "empty", raw: []byte{}, code: safety.CodeMalformed},
		{name: "alias-cycle", raw: []byte("a: &a\n  b: *a\n"), code: safety.CodeAliasLimit},
		{name: "secret-malformed", raw: []byte("services:\n  web:\n    environment:\n      API_TOKEN: " + probe + "\n    image: [\n"), code: safety.CodeMalformed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			start := time.Now()
			doc, err := parseNoPanic(t, fileFrom(tc.name+".yaml", tc.raw))
			if time.Since(start) > 5*time.Second {
				t.Fatalf("hang: took %s", time.Since(start))
			}
			if doc != nil {
				t.Fatal("expected no document")
			}
			if err == nil {
				t.Fatal("expected typed error")
			}
			if safety.CodeOf(err) != tc.code {
				t.Fatalf("code=%s want %s err=%v", safety.CodeOf(err), tc.code, err)
			}
			msg := SafeErrorMessage(err)
			if strings.Contains(msg, probe) || strings.Contains(err.Error(), probe) {
				t.Fatalf("secret leaked: %s", err)
			}
			if err := safety.GuardMessage(err.Error(), []string{probe}); err != nil && tc.name == "secret-malformed" {
				t.Fatal(err)
			}
		})
	}
}

func TestValidOrdinaryAndNearBound(t *testing.T) {
	ordinary := []byte("services:\n  web:\n    image: alpine\n")
	doc, err := parseNoPanic(t, fileFrom("ordinary.yaml", ordinary))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 1 || doc.Services[0].Name != "web" {
		t.Fatalf("%+v", doc.Services)
	}
	near := nestedYAML(48)
	doc, err = parseNoPanic(t, fileFrom("near.yaml", near))
	if err != nil {
		t.Fatal(err)
	}
	if doc == nil {
		t.Fatal("near-bound should parse")
	}
}

func TestAnchorsStillParse(t *testing.T) {
	doc, err := parseNoPanic(t, loadFixture(t, "anchors.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 2 {
		t.Fatalf("services=%d", len(doc.Services))
	}
}

func TestValidFileEngineAcceptance(t *testing.T) {
	testenv.RequireDocker(t)
	dir := t.TempDir()
	body := []byte("services:\n  web:\n    image: alpine\n")
	p := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(p, body, 0o644); err != nil {
		t.Fatal(err)
	}
	doc, err := parseNoPanic(t, fileFrom(p, body))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 1 {
		t.Fatalf("services=%d", len(doc.Services))
	}
	cmd := exec.Command("docker", "compose", "--project-directory", dir, "-f", p, "config")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("engine rejected valid file: %v\n%s", err, out)
	}
}

func TestSecretDiagnosticNeverEchoes(t *testing.T) {
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	err := safety.NewParseError(safety.CodeMalformed, "compose.yaml", "token "+probe+" in input")
	if strings.Contains(err.Error(), probe) {
		t.Fatalf("leaked: %s", err)
	}
	if err := safety.Guard([]byte(err.Error()), []string{probe}); err != nil {
		t.Fatal(err)
	}
}

func TestUTF8RejectsInvalid(t *testing.T) {
	raw := []byte{0xff, 0xfe, 0x00, 0x01}
	if utf8.Valid(raw) {
		t.Fatal("fixture is valid utf8")
	}
	_, err := parseNoPanic(t, fileFrom("bin.yaml", raw))
	if safety.CodeOf(err) != safety.CodeEncoding {
		t.Fatalf("got %s %v", safety.CodeOf(err), err)
	}
}

func FuzzParseDoesNotPanic(f *testing.F) {
	f.Add([]byte("services:\n  web:\n    image: alpine\n"))
	f.Add([]byte{0xff, 0xfe})
	f.Add([]byte("["))
	f.Add([]byte("a: &a\n  b: *a\n"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 32*1024 {
			raw = raw[:32*1024]
		}
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic: %v", rec)
			}
		}()
		_, _ = Parse(fileFrom("fuzz.yaml", raw))
	})
}
