// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/exitcode"
	"composelens/internal/report"
)

// A base + override project has two services, not three. The report
// data lists unique services with each declaration's file and line, and the
// HTML viewer counts and lists those.
func TestReportCountsUniqueServicesWithDeclarations(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml":          "services:\n  web:\n    image: alpine:3.21\n  db:\n    image: postgres:17\n",
		"compose.override.yaml": "services:\n  web:\n    environment:\n      APP_ENV: override\n",
	})
	rt, out, errb := reportRT(dir)
	if code := rt.Run([]string{"report", "--json", "--no-engine", "--project-directory", dir}); code != exitcode.OK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var pkg struct {
		Source struct {
			Services       []any `json:"services"`
			ServiceSummary []struct {
				Name         string `json:"name"`
				Declarations []struct {
					File string `json:"file"`
					Line int    `json:"line"`
				} `json:"declarations"`
			} `json:"serviceSummary"`
		} `json:"source"`
	}
	if err := json.Unmarshal(out.Bytes(), &pkg); err != nil {
		t.Fatal(err)
	}
	if len(pkg.Source.Services) != 3 {
		t.Fatalf("declarations list changed: %d", len(pkg.Source.Services))
	}
	var names []string
	for _, s := range pkg.Source.ServiceSummary {
		names = append(names, s.Name)
		if s.Name == "web" && (len(s.Declarations) != 2 || s.Declarations[0].Line != 2 || s.Declarations[1].Line != 2 ||
			!strings.HasSuffix(s.Declarations[1].File, "compose.override.yaml")) {
			t.Errorf("web declarations: %+v", s.Declarations)
		}
	}
	if strings.Join(names, ",") != "db,web" {
		t.Errorf("unique services: %v", names)
	}
	page, err := report.HTML(out.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if !strings.Contains(html, `tile(overview, uniq.length, "Services")`) || !strings.Contains(html, "declared in") {
		t.Error("viewer does not count and label unique services")
	}
}
