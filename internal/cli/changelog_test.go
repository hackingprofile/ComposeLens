// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/enginecap"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
)

// The current version summary in CHANGELOG.md matches behaviour:
// check exits 6 when error findings remain, and the engine capability map is
// the Compose v2+ family (v5.4.0 is recognized).
func TestChangelogMatchesBehaviour(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	start := strings.Index(text, "## [0.1.0]")
	if start < 0 {
		t.Fatal("no current version section")
	}
	summary := text[start:]
	if end := strings.Index(summary[1:], "\n## ["); end >= 0 {
		summary = summary[:end+1]
	}

	lab := filepath.Join("..", "..", "examples", "check-lab", "required-unset")
	rt, _, errb := reportRT(lab)
	if code := rt.Run([]string{"check", "--json", "--project-directory", lab}); code != exitcode.Assertion {
		t.Fatalf("required-unset check exit=%d (want %d) err=%s", code, exitcode.Assertion, errb.String())
	}
	if strings.Contains(summary, "Exit 0 when the report completes") {
		t.Error("changelog says check exits 0 when the report completes")
	}
	if !strings.Contains(summary, "exit `6`") {
		t.Error("changelog does not state that remaining error findings exit 6")
	}

	if got := enginecap.FromDetect(evidence.Known, "v5.4.0").Support; got != enginecap.SupportRecognized {
		t.Fatalf("v5.4.0 support=%s", got)
	}
	if strings.Contains(summary, "Docker Compose v2 window") || !strings.Contains(summary, "Compose v2+") {
		t.Error("changelog must describe the recognized Compose v2+ family")
	}
}
