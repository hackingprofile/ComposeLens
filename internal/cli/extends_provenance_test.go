// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

// crossFileExtends is the single-level case: c in compose.yaml extends base
// in sub/base.yaml. X and API_TOKEN are inherited from line 4 of the base.
func crossFileExtends(t *testing.T) string {
	return writeProject(t, map[string]string{
		"compose.yaml": "services:\n" +
			"  c:\n" +
			"    extends: {file: sub/base.yaml, service: base}\n" +
			"    environment: {Y: c}\n",
		"sub/base.yaml": "services:\n" +
			"  base:\n" +
			"    image: busybox\n" +
			"    environment: {X: base, Y: base, API_TOKEN: inlinebasesecret1}\n",
	})
}

// nestedCrossFileExtends is two levels: c (compose.yaml) extends mid
// (sub/mid.yaml), which extends root (deep/root.yaml).
func nestedCrossFileExtends(t *testing.T) string {
	return writeProject(t, map[string]string{
		"compose.yaml": "services:\n" +
			"  c:\n" +
			"    extends: {file: sub/mid.yaml, service: mid}\n" +
			"    environment: {Y: c}\n",
		"sub/mid.yaml": "services:\n" +
			"  mid:\n" +
			"    extends: {file: ../deep/root.yaml, service: root}\n" +
			"    environment: {M: mid}\n",
		"deep/root.yaml": "services:\n" +
			"  root:\n" +
			"    image: busybox\n" +
			"    environment: {R: root, API_TOKEN: inlinerootsecret2}\n",
	})
}

type stageLoc struct {
	Name   string `json:"name"`
	Winner string `json:"winner"`
	Source string `json:"source"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

func explainStages(t *testing.T, dir, target string) []stageLoc {
	t.Helper()
	code, out, errs := runIn(t, dir, nil, "explain", "--json", target)
	if code != 0 {
		t.Fatalf("explain %s: exit %d %s", target, code, errs)
	}
	var rep struct {
		Stages []stageLoc `json:"stages"`
	}
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	return rep.Stages
}

func assertStageFile(t *testing.T, dir, target, stage, wantRel string, wantLine int) {
	t.Helper()
	want := filepath.Join(dir, filepath.FromSlash(wantRel))
	for _, st := range explainStages(t, dir, target) {
		if st.Name != stage {
			continue
		}
		// The container-environment stage names the file in source; winner
		// is the source kind there.
		got := st.Winner
		if stage == "container-environment" {
			got = st.Source
		}
		if !strings.EqualFold(got, want) || st.Line != wantLine {
			t.Errorf("%s %s stage at %s:%d, want %s:%d", target, stage, got, st.Line, want, wantLine)
		}
		return
	}
	t.Errorf("%s has no %s stage", target, stage)
}

func TestCrossFileExtendsProvenanceNamesBaseFile(t *testing.T) {
	dir := crossFileExtends(t)
	assertStageFile(t, dir, "services.c.environment.X", "merge", "sub/base.yaml", 4)
	assertStageFile(t, dir, "services.c.image", "merge", "sub/base.yaml", 3)
	assertStageFile(t, dir, "services.c.environment.Y", "merge", "compose.yaml", 4)
	assertStageFile(t, dir, "c:X", "container-environment", "sub/base.yaml", 4)
	assertStageFile(t, dir, "c:Y", "container-environment", "compose.yaml", 4)
}

func TestNestedCrossFileExtendsProvenanceNamesEachFile(t *testing.T) {
	dir := nestedCrossFileExtends(t)
	assertStageFile(t, dir, "services.c.environment.R", "merge", "deep/root.yaml", 4)
	assertStageFile(t, dir, "services.c.image", "merge", "deep/root.yaml", 3)
	assertStageFile(t, dir, "services.c.environment.M", "merge", "sub/mid.yaml", 4)
	assertStageFile(t, dir, "services.c.environment.Y", "merge", "compose.yaml", 4)
	assertStageFile(t, dir, "c:R", "container-environment", "deep/root.yaml", 4)
}

func TestCrossFileExtendsAnnotationsAndSARIFNameBaseFile(t *testing.T) {
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	for name, tc := range map[string]struct {
		dir  string
		file string
	}{
		"single": {crossFileExtends(t), "sub/base.yaml"},
		"nested": {nestedCrossFileExtends(t), "deep/root.yaml"},
	} {
		_, out, errs := runIn(t, tc.dir, nil, "check", "--github")
		if !strings.Contains(out+errs, "file="+tc.file+",line=4") {
			t.Errorf("%s: annotation does not name %s:4:\n%s%s", name, tc.file, out, errs)
		}
		_, sarif, _ := runIn(t, tc.dir, nil, "check", "--sarif")
		if !strings.Contains(sarif, `"uri": "`+tc.file+`"`) {
			t.Errorf("%s: SARIF physicalLocation does not name %s:\n%s", name, tc.file, sarif)
		}
	}
}
