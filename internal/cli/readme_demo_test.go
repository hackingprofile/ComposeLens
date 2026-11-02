// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

// The README's explain/check demo is a shipped fixture
// (examples/readme-demo) and the README text matches what it produces:
// production wins with no container loser (.env is an interpolation source,
// not injected), and check reports only CHK01.
func TestReadmeDemoReproducesTheReadme(t *testing.T) {
	root := filepath.Join("..", "..")
	demo := filepath.Join(root, "examples", "readme-demo")
	if _, err := os.Stat(filepath.Join(demo, "compose.yaml")); err != nil {
		t.Fatalf("examples/readme-demo is missing: %v", err)
	}
	rt, out, errb := reportRT(demo)
	if code := rt.Run([]string{"explain", "api:APP_ENV", "--json", "--project-directory", demo}); code != exitcode.OK {
		t.Fatalf("explain code=%d err=%s", code, errb.String())
	}
	var ex struct {
		Effective struct {
			Text *string `json:"text"`
		} `json:"effective"`
		Stages []struct {
			Name       string   `json:"name"`
			Overridden []string `json:"overridden"`
		} `json:"stages"`
	}
	if err := json.Unmarshal(out.Bytes(), &ex); err != nil {
		t.Fatal(err)
	}
	if ex.Effective.Text == nil || *ex.Effective.Text != "production" {
		t.Fatalf("effective: %v", ex.Effective.Text)
	}
	for _, st := range ex.Stages {
		if st.Name == "container-environment" && len(st.Overridden) != 0 {
			t.Errorf("unexpected container loser: %v", st.Overridden)
		}
	}
	rt, out, errb = reportRT(demo)
	rt.Run([]string{"check", "--json", "--project-directory", demo})
	var ck struct {
		Findings []struct {
			ID string `json:"id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &ck); err != nil {
		t.Fatalf("check: %v %s", err, errb.String())
	}
	var ids []string
	for _, f := range ck.Findings {
		ids = append(ids, f.ID)
	}
	if strings.Join(ids, ",") != "CHK01" {
		t.Errorf("check findings %v, README says only CHK01", ids)
	}

	raw, err := os.ReadFile(filepath.Join(root, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	if !strings.Contains(readme, "examples/readme-demo") {
		t.Error("README does not name the demo fixture")
	}
	for _, alt := range regexp.MustCompile(`alt="([^"]*)"`).FindAllStringSubmatch(readme, -1) {
		a := alt[1]
		if strings.Contains(a, "CHK05") || strings.Contains(a, "overridden, not injected") {
			t.Errorf("alt text claims output the demo does not produce: %q", a)
		}
	}
}
