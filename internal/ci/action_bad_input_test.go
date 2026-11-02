// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestActionFailsOnMissingProjectDirectory builds the real CLI through the
// action wrapper and points it at a project directory that does not exist.
func TestActionFailsOnMissingProjectDirectory(t *testing.T) {
	shells := wrapperShells(t)
	if len(shells) == 0 {
		t.Skip("neither PowerShell nor bash is available")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	for shell, argv := range shells {
		for _, failOn := range []string{"error", "never"} {
			tmp := t.TempDir()
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Env = append(os.Environ(),
				"COMPOSELENS_ACTION_PATH="+filepath.ToSlash(root),
				"RUNNER_TEMP="+filepath.ToSlash(tmp),
				"INPUT_PROJECT_DIRECTORY="+filepath.ToSlash(filepath.Join(tmp, "does", "not", "exist")),
				"INPUT_FAIL_ON="+failOn,
				"GITHUB_OUTPUT=",
				"GITHUB_STEP_SUMMARY=",
			)
			out, err := cmd.CombinedOutput()
			if err == nil {
				t.Errorf("%s fail-on=%s: action passed for a missing project directory:\n%s", shell, failOn, out)
			}
		}
	}
}
