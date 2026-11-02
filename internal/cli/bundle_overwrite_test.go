// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

func TestDoctorBundleRefusesToOverwriteAFile(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": "keep\n"})
	code, _, errs := runIn(t, dir, nil, "doctor", "--bundle", "compose.yaml")
	if code != exitcode.Input || !strings.Contains(errs, "output-exists") {
		t.Errorf("exit %d stderr=%s, want exit 3 output-exists", code, errs)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "compose.yaml"))
	if err != nil || string(raw) != "keep\n" {
		t.Errorf("the existing file was changed: %q %v", raw, err)
	}
	code, _, errs = runIn(t, dir, nil, "doctor", "--bundle", "bundle.json")
	if code != 0 {
		t.Fatalf("a new bundle path must work: exit %d %s", code, errs)
	}
	if _, err := os.Stat(filepath.Join(dir, "bundle.json")); err != nil {
		t.Error(err)
	}
}
