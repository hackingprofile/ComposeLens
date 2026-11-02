// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestExampleWorkflowPassesThroughBothWrappers(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "example-composelens.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf workflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	var inputs map[string]string
	for _, job := range wf.Jobs {
		for _, step := range job.Steps {
			if step.Uses == "./" {
				inputs = step.With
			}
		}
	}
	if inputs["project-directory"] == "" || inputs["fail-on"] == "" {
		t.Fatal("example Action inputs missing")
	}
	shells := wrapperShells(t)
	if len(shells) == 0 {
		t.Skip("neither PowerShell nor bash is available")
	}
	for shell, argv := range shells {
		t.Run(shell, func(t *testing.T) {
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Dir = root
			cmd.Env = append(os.Environ(),
				"COMPOSELENS_ACTION_PATH="+filepath.ToSlash(root),
				"RUNNER_TEMP="+filepath.ToSlash(t.TempDir()),
				"INPUT_PROJECT_DIRECTORY="+inputs["project-directory"],
				"INPUT_FAIL_ON="+inputs["fail-on"],
				"INPUT_EMIT_JSON="+inputs["emit-json"],
				"INPUT_EMIT_SARIF="+inputs["emit-sarif"],
				"INPUT_EMIT_SUMMARY="+inputs["emit-summary"],
				"INPUT_EMIT_ANNOTATIONS="+inputs["emit-annotations"],
				"GITHUB_OUTPUT=", "GITHUB_STEP_SUMMARY=",
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("example workflow failed: %v\n%s", err, out)
			}
		})
	}
}
