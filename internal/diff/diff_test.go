// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/envsrc"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func snapshot(t *testing.T, dir string, names, envFiles, flagProfiles []string) explain.Input {
	t.Helper()
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	table, err := interp.Load(dir, envFiles, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
	}
	var overlay []*composeparse.Document
	chains := map[string][]string{}
	var items []interp.Value
	seen := map[string]bool{}
	for _, name := range names {
		p := filepath.Join(dir, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, interp.ResolveScalars(composeparse.StringScalars(doc), table, fp)...)
		seen[doc.File.Path] = true
		expanded := include.Expand(doc, include.DiskLoad, table)
		overlay = append(overlay, expanded.Docs...)
		for k, v := range expanded.Chains {
			if _, ok := chains[k]; !ok {
				chains[k] = v
			}
		}
		for _, d := range expanded.Docs {
			if d != nil && !seen[d.File.Path] {
				seen[d.File.Path] = true
				items = append(items, interp.ResolveScalars(composeparse.StringScalars(d), table, fp)...)
			}
		}
	}
	extOrigins := map[string]extends.Field{}
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.DiskLoad, table)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
		for _, f := range er.Fields {
			extOrigins[f.Path] = f
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(flagProfiles, nil)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(nil), table)
	if err != nil {
		t.Fatal(err)
	}
	return explain.Input{
		Interp:    items,
		Merge:     merged,
		Chains:    chains,
		Extends:   extOrigins,
		Profiles:  profiles.Activate(merged, active),
		Container: cen,
	}
}

func fixture(t *testing.T, name string, envFiles, profiles []string) explain.Input {
	t.Helper()
	dir := filepath.Join("..", "..", "fixtures", "diff", name)
	return snapshot(t, dir, []string{"compose.yaml"}, envFiles, profiles)
}

func findChange(r Result, kind, target string) (Change, bool) {
	for _, c := range r.Changes {
		if c.Kind == kind && c.Target == target {
			return c, true
		}
	}
	return Change{}, false
}

func TestIdenticalConfigsEmptyDiff(t *testing.T) {
	in := fixture(t, "profiles", nil, nil)
	r := Compare(in, in)
	if len(r.Changes) != 0 {
		t.Fatalf("expected empty, got %+v", r.Changes)
	}
}

func TestProfileEnablesServiceAddedRemoved(t *testing.T) {
	left := fixture(t, "profiles", nil, nil)
	right := fixture(t, "profiles", nil, []string{"debug"})
	r := Compare(left, right)
	ch, ok := findChange(r, KindService, "debug")
	if !ok || ch.Change != ChangeAdded {
		t.Fatalf("expected debug added, got %+v", r.Changes)
	}
	if ch.Left.Present || !ch.Right.Present || ch.Right.State != profiles.StateEnabled {
		t.Fatalf("%+v", ch)
	}
	back := Compare(right, left)
	ch, ok = findChange(back, KindService, "debug")
	if !ok || ch.Change != ChangeRemoved {
		t.Fatalf("expected debug removed, got %+v", back.Changes)
	}
}

func TestContainerEnvWinningSourceDiffers(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "diff", "env-source")
	left := snapshot(t, dir, []string{"compose.yaml"}, []string{"left.interp.env"}, nil)
	right := snapshot(t, dir, []string{"compose.yaml"}, []string{"right.interp.env"}, nil)
	r := Compare(left, right)
	ch, ok := findChange(r, KindEnv, "web:COLOR")
	if !ok || ch.Change != ChangeChanged {
		t.Fatalf("expected COLOR changed, got %+v", r.Changes)
	}
	if ch.Left.Effective != "from-left" || ch.Right.Effective != "from-right" {
		t.Fatalf("values %+v", ch)
	}
	if ch.Left.Source == ch.Right.Source || ch.Left.Source == "" || ch.Right.Source == "" {
		t.Fatalf("sources %+v / %+v", ch.Left.Source, ch.Right.Source)
	}
	if !strings.Contains(ch.Left.Source, "env-file") || !strings.Contains(ch.Right.Source, "env-file") {
		t.Fatalf("want env-file sources %+v", ch)
	}
	if !strings.Contains(ch.Left.Source, "left.env") || !strings.Contains(ch.Right.Source, "right.env") {
		t.Fatalf("want distinct files %+v", ch)
	}
}

func TestEnvPresentOnOneSideOnly(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "diff", "env-source")
	left := snapshot(t, dir, []string{"compose.yaml"}, []string{"left.interp.env"}, nil)
	right := snapshot(t, dir, []string{"compose.yaml"}, []string{"right.interp.env"}, nil)
	r := Compare(left, right)
	ch, ok := findChange(r, KindEnv, "web:ONLY_LEFT")
	if !ok || ch.Change != ChangeRemoved {
		t.Fatalf("expected ONLY_LEFT removed on right, got %+v", r.Changes)
	}
	if !ch.Left.Present || ch.Right.Present {
		t.Fatalf("%+v", ch)
	}
}

func TestSecretValueDiffersRedactedMaterial(t *testing.T) {
	leftTok := "synthetic-merge-token-overlay"
	rightTok := "synthetic-merge-token-value"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${TOKEN}\n",
		"left.env":     "TOKEN=" + leftTok + "\n",
		"right.env":    "TOKEN=" + rightTok + "\n",
	})
	left := snapshot(t, dir, []string{"compose.yaml"}, []string{"left.env"}, nil)
	right := snapshot(t, dir, []string{"compose.yaml"}, []string{"right.env"}, nil)
	r := Compare(left, right)
	ch, ok := findChange(r, KindEnv, "web:API_TOKEN")
	if !ok || ch.Change != ChangeChanged || !ch.Secret {
		t.Fatalf("%+v", r.Changes)
	}
	frags := SecretFragments(r)
	foundLeft, foundRight := false, false
	for _, f := range frags {
		if strings.Contains(f, leftTok) {
			foundLeft = true
		}
		if strings.Contains(f, rightTok) {
			foundRight = true
		}
	}
	if !foundLeft || !foundRight {
		t.Fatalf("fragments %v", frags)
	}
}

func TestCanonicalShortLongPortsNoCosmeticDiff(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "ports", "short"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "ports", "long"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	if _, ok := findChange(r, KindField, "services.web.ports"); ok {
		t.Fatalf("equivalent ports must not diff: %+v", r.Changes)
	}
	for _, c := range r.Changes {
		if strings.Contains(c.Target, ".ports") {
			t.Fatalf("cosmetic ports path %s in %+v", c.Target, r.Changes)
		}
	}
}

func TestCanonicalUnequalPortsDiffers(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "ports", "short"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "ports", "unequal"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	ch, ok := findChange(r, KindField, "services.web.ports")
	if !ok || ch.Change != ChangeChanged {
		t.Fatalf("expected ports changed, got %+v", r.Changes)
	}
}

func TestCanonicalLabelsListMapNoCosmeticDiff(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "labels", "list"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "labels", "map"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	if _, ok := findChange(r, KindField, "services.web.labels"); ok {
		t.Fatalf("equivalent labels must not diff: %+v", r.Changes)
	}
	for _, c := range r.Changes {
		if strings.Contains(c.Target, ".labels") {
			t.Fatalf("cosmetic labels path %s in %+v", c.Target, r.Changes)
		}
	}
}

func TestCanonicalCommandShellVsExecDiffers(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "command", "shell"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "command", "exec-flow"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	ch, ok := findChange(r, KindField, "services.web.command")
	if !ok || ch.Change != ChangeChanged {
		t.Fatalf("shell vs exec must differ: %+v", r.Changes)
	}
}

func TestCanonicalExecFlowBlockNoDiff(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "command", "exec-flow"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "command", "exec-block"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	if _, ok := findChange(r, KindField, "services.web.command"); ok {
		t.Fatalf("exec flow vs block must not diff: %+v", r.Changes)
	}
	if _, ok := findChange(r, KindField, "services.web.entrypoint"); ok {
		t.Fatalf("entrypoint flow vs block must not diff: %+v", r.Changes)
	}
}

func TestCanonicalHealthcheckStringCMDShellNoDiff(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "healthcheck", "string"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "healthcheck", "cmd-shell"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	if _, ok := findChange(r, KindField, "services.web.healthcheck.test"); ok {
		t.Fatalf("string vs CMD-SHELL must not diff: %+v", r.Changes)
	}
}

func TestCanonicalHealthcheckStringVsCMDDiffers(t *testing.T) {
	left := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "healthcheck", "string"), []string{"compose.yaml"}, nil, nil)
	right := snapshot(t, filepath.Join("..", "..", "fixtures", "normalize", "healthcheck", "cmd"), []string{"compose.yaml"}, nil, nil)
	r := Compare(left, right)
	ch, ok := findChange(r, KindField, "services.web.healthcheck.test")
	if !ok || ch.Change != ChangeChanged {
		t.Fatalf("string vs CMD must differ: %+v", r.Changes)
	}
}
