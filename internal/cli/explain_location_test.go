// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

// explain names the winning file AND line (and column), in JSON and
// in the human view, as the README promises.
func TestExplainCarriesWinningLineAndColumn(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml":          "services:\n  web:\n    image: alpine:3.21\n    environment:\n      APP_ENV: base\n",
		"compose.override.yaml": "services:\n  web:\n    environment:\n      APP_ENV: override\n",
	})
	cases := []struct {
		target, stage string
		line          int
		file          string
	}{
		{"services.web.image", "merge", 3, "compose.yaml"},
		{"web:APP_ENV", "container-environment", 4, "compose.override.yaml"},
	}
	for _, c := range cases {
		rt, out, errb := reportRT(dir)
		if code := rt.Run([]string{"explain", c.target, "--json", "--project-directory", dir}); code != exitcode.OK {
			t.Fatalf("%s: code=%d err=%s", c.target, code, errb.String())
		}
		var rep struct {
			Stages []struct {
				Name   string `json:"name"`
				Line   int    `json:"line"`
				Column int    `json:"column"`
			} `json:"stages"`
		}
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, st := range rep.Stages {
			if st.Name == c.stage {
				found = true
				if st.Line != c.line {
					t.Errorf("%s %s: line=%d want %d", c.target, c.stage, st.Line, c.line)
				}
				if c.stage == "merge" && st.Column <= 0 {
					t.Errorf("%s merge: column=%d", c.target, st.Column)
				}
			}
		}
		if !found {
			t.Errorf("%s: no %s stage", c.target, c.stage)
		}
		rt, out, _ = reportRT(dir)
		rt.Run([]string{"explain", c.target, "--project-directory", dir})
		if want := c.file + ":" + itoa(c.line); !strings.Contains(out.String(), want) {
			t.Errorf("%s human: no %q in\n%s", c.target, want, out.String())
		}
	}
}

func itoa(n int) string {
	b, _ := json.Marshal(n)
	return string(b)
}
