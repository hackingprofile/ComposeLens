// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type fakeTB struct {
	testing.TB
	skipped, failed bool
}

func (f *fakeTB) Helper()              {}
func (f *fakeTB) Skip(...any)          { f.skipped = true }
func (f *fakeTB) Fatal(...any)         { f.failed = true }
func (f *fakeTB) Skipf(string, ...any) { f.skipped = true }

// Without a Docker CLI on PATH a live test skips cleanly; with
// COMPOSELENS_REQUIRE_DOCKER=1 it fails instead of passing silently.
func TestRequireDockerSkipsOrFails(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv(EnvRequireDocker, "")
	f := &fakeTB{}
	RequireDocker(f)
	if !f.skipped || f.failed {
		t.Fatalf("no docker, not required: skipped=%v failed=%v", f.skipped, f.failed)
	}
	t.Setenv(EnvRequireDocker, "1")
	f = &fakeTB{}
	RequireDocker(f)
	if !f.failed {
		t.Fatal("no docker, required: the test did not fail")
	}
}

// No test hard-fails on a missing Docker CLI; every test that looks
// for docker goes through RequireDocker (or skips itself).
func TestNoTestFailsForMissingDocker(t *testing.T) {
	root := filepath.Join("..", "..")
	fatal := regexp.MustCompile(`LookPath\("docker"\)[^\n]*\n[^\n]*\n?[^\n]*t\.Fatal|t\.Fatal\("docker CLI required`)
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(p, "_test.go") || strings.Contains(p, "testenv") {
			return nil
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		if fatal.Match(raw) {
			t.Errorf("%s fails instead of skipping when docker is absent", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The docs and CI say what the suite does without Docker.
func TestDocsAndCIStateTheDockerRule(t *testing.T) {
	root := filepath.Join("..", "..")
	// ci.yml requires Docker per matrix leg: the variable comes from the matrix
	// and at least one leg sets it to "1".
	for rel, wants := range map[string][]string{
		filepath.Join("docs", "quickstart.md"):          {EnvRequireDocker},
		"CONTRIBUTING.md":                               {EnvRequireDocker},
		filepath.Join(".github", "workflows", "ci.yml"): {EnvRequireDocker + ": ${{ matrix.require_docker }}", `require_docker: "1"`},
	} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range wants {
			if !strings.Contains(string(raw), want) {
				t.Errorf("%s does not state %q", rel, want)
			}
		}
		if strings.Contains(string(raw), "they do not skip") {
			t.Errorf("%s still says live tests do not skip", rel)
		}
	}
}
