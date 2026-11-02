// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/report"
)

func TestReportFixtureSafety(t *testing.T) {
	for _, tc := range []struct{ name, payload string }{
		{"xss-script", "<script>alert(1)</script>"},
		{"xss-event", "\"><img src=x onerror=alert(1)>"},
		{"xss-javascript-url", "javascript:alert(1)"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(fixturesRoot(t), "security", "report-xss", tc.name)
			code, page, errb := runCorpusCLI(t, dir, []string{"report", "--html", "--no-engine", "--project-directory", dir})
			if code != 0 {
				t.Fatalf("report exit=%d: %s", code, errb)
			}
			if sinks := report.LiveSinks([]byte(page)); len(sinks) != 0 {
				t.Fatalf("live HTML sinks: %v", sinks)
			}
			if refs := report.RemoteRefs([]byte(page)); len(refs) != 0 {
				t.Fatalf("remote references: %v", refs)
			}
			island, err := report.DataIslandJSON([]byte(page))
			if err != nil {
				t.Fatal(err)
			}
			var data any
			if err := json.Unmarshal(island, &data); err != nil {
				t.Fatal(err)
			}
			decoded, err := json.Marshal(data)
			if err != nil {
				t.Fatal(err)
			}
			want, err := json.Marshal(tc.payload)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(decoded), string(want)) {
				t.Fatalf("payload absent from report data: %s", tc.name)
			}
		})
	}
}
