// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDoctorBundleAndArtifactsNeverFollowSymlinks(t *testing.T) {
	dir := writeProject(t, map[string]string{"victim.txt": "keep\n", "compose.yaml": "services:\n  w:\n    image: nginx\n"})
	if err := os.Symlink(filepath.Join(dir, "victim.txt"), filepath.Join(dir, "link.json")); err != nil {
		t.Skipf("symlink: %v", err)
	}
	if code, _, _ := runIn(t, dir, nil, "doctor", "--bundle", "link.json"); code == 0 {
		t.Error("doctor --bundle wrote through a symlink")
	}
	clearGitHubEnv(t)
	t.Setenv("COMPOSELENS_JSON_PATH", filepath.Join(dir, "link.json"))
	runIn(t, dir, nil, "check", "--github")
	if raw, _ := os.ReadFile(filepath.Join(dir, "victim.txt")); string(raw) != "keep\n" {
		t.Errorf("a symlinked artifact path overwrote its target: %q", raw)
	}
}
