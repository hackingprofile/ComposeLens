// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// An ordinary scratch-style folder name in the project path keeps
// diff source provenance (it is not redacted as a secret).
func TestLongScratchPathKeepsDiffSources(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "project_snapshot_12345678_4b7d2e9c", "env-source")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"compose.yaml":     "services:\n  web:\n    image: alpine\n    env_file:\n      - ${SIDE_FILE}\n",
		"left.env":         "COLOR=from-left\nONLY_LEFT=yes\n",
		"left.interp.env":  "SIDE_FILE=left.env\n",
		"right.env":        "COLOR=from-right\n",
		"right.interp.env": "SIDE_FILE=right.env\n",
	}
	for n, b := range files {
		if err := os.WriteFile(filepath.Join(dir, n), []byte(b), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	rt, out, errb := reportRT(dir)
	if code := rt.Run([]string{"diff", "--json", "--left-env-file", "left.interp.env", "--right-env-file", "right.interp.env", "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep diffReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range rep.Changes {
		if c.Target == "web:COLOR" {
			found = true
			if !strings.HasSuffix(c.Left.Source, "left.env") || !strings.HasSuffix(c.Right.Source, "right.env") {
				t.Fatalf("sources lost: left=%q right=%q", c.Left.Source, c.Right.Source)
			}
		}
	}
	if !found {
		t.Fatalf("no web:COLOR change: %s", out.String())
	}
}
