// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestDocumentedQuickstartBinaryPath(t *testing.T) {
	root := filepath.Join("..", "..")
	files := []string{
		filepath.Join(root, "README.md"),
		filepath.Join(root, "docs", "quickstart.md"),
	}
	wrong := regexp.MustCompile(`(?m)^(?:[ \t]*)\.\./composelens(?:\.exe)?(?:[ \t]|$)`)
	needWin := "../../composelens.exe"
	needUnix := "../../composelens"
	for _, p := range files {
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, "cd examples/precedence-lab") {
			t.Fatalf("%s missing cd examples/precedence-lab", p)
		}
		if wrong.MatchString(text) {
			t.Fatalf("%s still uses one-level-up binary path after the lab cd", p)
		}
		if !strings.Contains(text, needWin) {
			t.Fatalf("%s missing %s", p, needWin)
		}
		if filepath.Base(filepath.Dir(p)) == "docs" && !strings.Contains(text, needUnix) && !strings.Contains(text, "Unix") {
			t.Fatalf("%s should mention Unix binary name", p)
		}
	}
}

// Every contract that lists the commands which start a local
// `docker compose config` must list report as well, and keep reproduce as
// print-only. The fix was documentation; this test keeps it from
// silently regressing.
func TestReportEngineCaptureIsDocumented(t *testing.T) {
	root := filepath.Join("..", "..")
	for _, rel := range []string{"SECURITY.md", filepath.Join("docs", "privacy.md"), filepath.Join("docs", "report.md")} {
		raw, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, line := range strings.Split(string(raw), "\n") {
			if strings.Contains(line, "report") && strings.Contains(line, "docker compose config") {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s does not say that report runs docker compose config", rel)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "docs", "privacy.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`reproduce\b.*does \*\*not\*\* execute`).Match(raw) {
		t.Error("docs/privacy.md must keep reproduce documented as print-only")
	}
}
