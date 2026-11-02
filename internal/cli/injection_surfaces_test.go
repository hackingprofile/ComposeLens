// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"composelens/internal/differential"
)

func TestTargetExplainEscapesWorkflowCommandValues(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": "services:\n  api:\n    image: nginx\n    environment:\n      NOTE: \"first\\n::error title=FromValue::forged\"\n"})
	code, out, errs := runIn(t, dir, nil, "explain", "api:NOTE")
	if code != 0 {
		t.Fatalf("explain: exit=%d stderr=%s", code, errs)
	}
	if bad := startsWorkflowCommand(out + errs); len(bad) != 0 {
		t.Errorf("forged workflow commands: %q", bad)
	}
	if strings.Count(out, `first\n::error title=FromValue::forged`) < 3 {
		t.Errorf("effective, merge and container values must remain visible and escaped:\n%s", out)
	}
}

func TestHumanPathWritersEscapeWorkflowCommands(t *testing.T) {
	path := "/projects/first\n::error title=FromDir::forged/compose.yaml"
	outputs := map[string]string{
		"inspect":      formatInspect(inspectReport{Includes: []IncludeGraphReport{{File: path, Refs: []IncludeRefReport{{Path: path, Resolved: path, Reason: path}}}}, Extends: []ExtendsGraphReport{{File: path, Refs: []ExtendsRefReport{{Resolved: path, Reason: path}}}}}),
		"differential": differential.Human(differential.Report{Command: "docker compose --project-directory " + path + " config", Version: path, SkipReason: path, Rows: []differential.Row{{Detail: path}}}),
		"reproduce":    formatReproduce(reproduceReport{Command: "docker compose " + path}),
	}
	for name, out := range outputs {
		if bad := startsWorkflowCommand(out); len(bad) != 0 {
			t.Errorf("%s starts workflow commands: %q", name, bad)
		}
		if !strings.Contains(out, `first\n::error`) {
			t.Errorf("%s lost escaped path", name)
		}
	}
}
