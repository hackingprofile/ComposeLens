// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

type fixtureFile struct {
	GOOS  string        `json:"goos"`
	Cases []fixtureCase `json:"cases"`
}

type fixtureCase struct {
	Name       string `json:"name"`
	ProjectDir string `json:"projectDir"`
	Relative   string `json:"relative"`
	WantSlash  string `json:"wantSlash"`
}

func TestJoinCleanFixtures(t *testing.T) {
	root := filepath.Join("..", "..", "fixtures", "paths")
	files := []string{"windows.json", "posix.json"}
	ran := 0
	for _, name := range files {
		p := filepath.Join(root, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("missing cross-platform fixture %s: %v", p, err)
		}
		var fx fixtureFile
		if err := json.Unmarshal(raw, &fx); err != nil {
			t.Fatal(err)
		}
		if !fixtureApplies(fx.GOOS) {
			t.Logf("fixture %s written for goos=%s; skipped on %s", name, fx.GOOS, runtime.GOOS)
			continue
		}
		for _, c := range fx.Cases {
			got := filepath.ToSlash(JoinClean(c.ProjectDir, c.Relative))
			if got != c.WantSlash {
				t.Fatalf("%s/%s: got %q want %q", name, c.Name, got, c.WantSlash)
			}
			ran++
		}
	}
	if ran == 0 {
		t.Fatalf("no path fixtures executed on GOOS=%s", runtime.GOOS)
	}
}

func fixtureApplies(goos string) bool {
	switch goos {
	case runtime.GOOS:
		return true
	case "posix":
		return runtime.GOOS != "windows"
	default:
		return false
	}
}

func TestCanonicalAbs(t *testing.T) {
	dir := t.TempDir()
	got, err := Canonical(filepath.Join(dir, "compose.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(got) {
		t.Fatalf("not absolute: %s", got)
	}
}
