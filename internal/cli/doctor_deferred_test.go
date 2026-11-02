// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

// Doctor's deferred feature ids say what is deferred. Local SARIF and the
// composite Action ship; their upload / live-run counterparts are deferred.
func TestDoctorDeferredIdsSayWhatIsDeferred(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services: {web: {image: alpine:3.21}}\n"})
	rt, out, errb := reportRT(dir)
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != exitcode.OK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep struct {
		Features struct {
			Deferred []string `json:"deferred"`
		} `json:"features"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	got := strings.Join(rep.Features.Deferred, ",")
	for _, bad := range []string{"sarif", "github-action"} {
		for _, d := range rep.Features.Deferred {
			if d == bad {
				t.Errorf("ambiguous deferred id %q in %s", bad, got)
			}
		}
	}
	for _, want := range []string{"sarif-upload", "github-action-live"} {
		if !strings.Contains(","+got+",", ","+want+",") {
			t.Errorf("deferred lacks %q: %s", want, got)
		}
	}
	rt, out, _ = reportRT(dir)
	rt.Run([]string{"doctor", "--project-directory", dir})
	if !strings.Contains(out.String(), "sarif-upload") || strings.Contains(out.String(), " sarif,") {
		t.Errorf("human doctor: %s", out.String())
	}
	doc, err := os.ReadFile(filepath.Join("..", "..", "docs", "check.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "`sarif-upload`") || !strings.Contains(string(doc), "`github-action-live`") {
		t.Error("docs/check.md does not name the deferred ids")
	}
}
