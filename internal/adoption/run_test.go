// SPDX-License-Identifier: Apache-2.0

package adoption

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"composelens/internal/cli"
	"composelens/internal/engine"
	"composelens/internal/evidence"
)

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatalf("repo root %s: %v", root, err)
	}
	return root
}

func TestDocumentedInvocationsPresentInDocs(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "examples.md"))
	if err != nil {
		t.Fatal(err)
	}
	docs := string(raw)
	for _, c := range Cases() {
		joined := strings.Join(c.Args, " ")
		if !strings.Contains(docs, joined) {
			t.Fatalf("%s missing from docs/examples.md: %s", c.ID, joined)
		}
	}
}

func TestAdoptionExamplesExecuteLocally(t *testing.T) {
	root := repoRoot(t)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	detect := func() engine.Info { return engine.Info{State: evidence.Absent} }
	for _, c := range Cases() {
		c := c
		t.Run(c.ID, func(t *testing.T) {
			var out, errb bytes.Buffer
			rt := cli.Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: detect}
			code := rt.Run(c.Args)
			if code != c.Exit {
				t.Fatalf("exit=%d want %d err=%s out=%s", code, c.Exit, errb.String(), out.String())
			}
			if !strings.Contains(out.String(), c.Contain) {
				t.Fatalf("missing %q in %s", c.Contain, out.String())
			}
			if strings.Contains(out.String()+errb.String(), "ghp_") {
				t.Fatal("token-shaped probe leaked")
			}
		})
	}
}

func TestAdoptionExamplesHaveNoRealSecrets(t *testing.T) {
	root := filepath.Join(repoRoot(t), "examples")
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		base := info.Name()
		if strings.HasSuffix(base, "-lab") && info.IsDir() {
			return filepath.SkipDir
		}
		rel, _ := filepath.Rel(root, path)
		if strings.HasPrefix(rel, "monorepo"+string(filepath.Separator)) || strings.HasPrefix(rel, "multi-project"+string(filepath.Separator)) {
			if info.IsDir() {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			text := string(raw)
			for _, bad := range []string{"ghp_", "gho_", "AKIA", "BEGIN PRIVATE"} {
				if strings.Contains(text, bad) {
					t.Errorf("%s contains %s", path, bad)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
