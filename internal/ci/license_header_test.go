// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const spdxLine = "// SPDX-License-Identifier: Apache-2.0"

// TestGoSourcesCarryLicenseHeader is the header policy of .licenserc.yaml,
// checked on every platform: each first-party Go file under cmd/ and
// internal/ starts with the SPDX line.
func TestGoSourcesCarryLicenseHeader(t *testing.T) {
	root := filepath.Join("..", "..")
	checked := 0
	for _, dir := range []string{"cmd", "internal"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(p string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() && d.Name() == "testdata" {
				return filepath.SkipDir
			}
			if d.IsDir() || !strings.HasSuffix(p, ".go") {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			checked++
			if !bytes.HasPrefix(raw, []byte(spdxLine+"\n")) {
				t.Errorf("%s does not start with %q", filepath.ToSlash(p), spdxLine)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 200 {
		t.Fatalf("checked %d Go files; the walk is wrong", checked)
	}
	cfg, err := os.ReadFile(filepath.Join(root, ".licenserc.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"SPDX-License-Identifier: Apache-2.0", `"cmd/**/*.go"`, `"internal/**/*.go"`} {
		if !bytes.Contains(cfg, []byte(want)) {
			t.Errorf(".licenserc.yaml does not contain %s", want)
		}
	}
}
