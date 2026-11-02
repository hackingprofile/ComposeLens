// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// The stable CLI goldens are OS-neutral: no recorded GOOS/GOARCH and no
// native path separators after the {project} placeholder, so the same files
// can be compared on any platform.
func TestGoldensAreOSNeutral(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "testdata", "golden", "*"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no goldens: %v", err)
	}
	platform := regexp.MustCompile(`"(os|arch)":\s*"(windows|linux|darwin|amd64|arm64|386)"`)
	nativeSep := regexp.MustCompile(`\{project\}[^"\s]*\\`)
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if platform.Match(raw) {
			t.Errorf("%s records the build platform", filepath.Base(f))
		}
		if nativeSep.Match(raw) {
			t.Errorf("%s records native path separators", filepath.Base(f))
		}
	}
}
