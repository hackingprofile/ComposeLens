// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/engineadapter"
	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
	"composelens/internal/testenv"
)

func TestLiveDifferentialThreeProjects(t *testing.T) {
	testenv.RequireDocker(t)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	projects := []struct {
		name  string
		dir   string
		files []string
	}{
		{name: "sequence-merge-lab", dir: filepath.Join(root, "examples", "sequence-merge-lab"), files: []string{"compose.yaml", "overlay.yaml"}},
		{name: "normalize-short", dir: filepath.Join(root, "examples", "normalize-lab"), files: []string{"compose.short.yaml"}},
		{name: "containerenv-lab", dir: filepath.Join(root, "examples", "containerenv-lab"), files: []string{"compose.yaml"}},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, p := range projects {
		t.Run(p.name, func(t *testing.T) {
			abs := make([]string, 0, len(p.files))
			for _, f := range p.files {
				abs = append(abs, filepath.Join(p.dir, f))
			}
			in := mustInternal(t, p.dir, abs)
			cap := engineadapter.DefaultRunner().Capture(ctx, engineadapter.Request{ProjectDir: p.dir, Files: abs})
			if cap.State != engineadapter.StateCaptured {
				t.Fatalf("engine state=%s detail=%s stderr=%s", cap.State, cap.Detail, cap.ConfigStderr)
			}
			eng, err := ParseConfig(cap.ConfigStdout)
			if err != nil {
				t.Fatal(err)
			}
			rep := CompareInputs(in, eng, Meta{
				EngineState: cap.State,
				Version:     cap.Version,
				Command:     cap.ConfigCommand,
				Project:     p.dir,
			})
			if len(rep.Rows) == 0 {
				t.Fatal("empty differential")
			}
			dumpEvidence(t, p.name, rep)
		})
	}
}

func mustInternal(t *testing.T, project string, files []string) explain.Input {
	t.Helper()
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	table, err := interp.Load(project, nil, project, os.Environ(), fp)
	if err != nil {
		t.Fatal(err)
	}
	var overlay []*composeparse.Document
	var getter interp.Getter
	if table != nil {
		getter = table
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := composeparse.Parse(discover.File{Path: path, Bytes: raw, Origin: "live"})
		if err != nil {
			t.Fatal(err)
		}
		expanded := include.Expand(doc, include.DiskLoad, getter)
		overlay = append(overlay, expanded.Docs...)
	}
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.DiskLoad, getter)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(nil, os.Environ())
	activated := profiles.Activate(merged, active)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(os.Environ()), getter)
	if err != nil {
		t.Fatal(err)
	}
	return explain.Input{Merge: merged, Profiles: activated, Container: cen}
}

func dumpEvidence(t *testing.T, name string, rep Report) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_DIFF_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	body := Human(rep)
	if err := os.WriteFile(filepath.Join(dir, name+".txt"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, '\n')
	if err := os.WriteFile(filepath.Join(dir, name+".json"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLiveEscapedLiteralMatchesEngineRuntime(t *testing.T) {
	testenv.RequireDocker(t)
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    environment:\n      LITERAL: $$VAR\n      LITERAL_BRACED: $${notavar}\n      MIXED: pre-$$HOME-post\n      GONE: $UNDEFINED\n      GONE_BRACED: ${UNDEFINED}\n"
	compose := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(compose, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	in := mustInternal(t, dir, []string{compose})
	got := map[string]string{}
	for _, se := range in.Container {
		if se.Service != "web" {
			continue
		}
		for _, v := range se.Vars {
			got[v.Key] = v.Value
		}
	}
	if got["LITERAL"] != "$VAR" {
		t.Fatalf("effective LITERAL %q (before-fix was empty)", got["LITERAL"])
	}
	if got["LITERAL_BRACED"] != "${notavar}" {
		t.Fatalf("effective LITERAL_BRACED %q", got["LITERAL_BRACED"])
	}
	if got["MIXED"] != "pre-$HOME-post" {
		t.Fatalf("effective MIXED %q (before-fix truncated $HOME)", got["MIXED"])
	}
	if got["GONE"] == "$UNDEFINED" || got["GONE_BRACED"] == "${UNDEFINED}" {
		t.Fatalf("over-correction %+v", got)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cap := engineadapter.DefaultRunner().Capture(ctx, engineadapter.Request{ProjectDir: dir, Files: []string{compose}})
	if cap.State != engineadapter.StateCaptured {
		t.Fatalf("engine state=%s detail=%s", cap.State, cap.Detail)
	}
	t.Logf("engine %s", cap.Version)
	if !strings.Contains(cap.ConfigStdout, "LITERAL: $$VAR") || !strings.Contains(cap.ConfigStdout, "MIXED: pre-$$HOME-post") {
		t.Fatalf("engine dump missing $$ escaping:\n%s", cap.ConfigStdout)
	}
	eng, err := ParseConfig(cap.ConfigStdout)
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: cap.State, Version: cap.Version})
	for _, path := range []string{"web:LITERAL", "web:LITERAL_BRACED", "web:MIXED"} {
		row := mustLiveRow(t, rep, path)
		if row.State != StateMatch {
			t.Fatalf("%s %+v", path, row)
		}
	}

	if dirEvidence := os.Getenv("COMPOSELENS_ESCAPED_LITERAL_EVIDENCE_DIR"); dirEvidence != "" {
		if err := os.MkdirAll(dirEvidence, 0o755); err != nil {
			t.Fatal(err)
		}
		out := "live-version " + cap.Version + "\n" +
			"dump keeps $$VAR / pre-$$HOME-post\n" +
			"effective LITERAL=" + got["LITERAL"] + " LITERAL_BRACED=" + got["LITERAL_BRACED"] + " MIXED=" + got["MIXED"] + "\n" +
			Human(rep)
		if err := os.WriteFile(filepath.Join(dirEvidence, "live-after.txt"), []byte(out), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dirEvidence, "07-engine-dump.txt"), []byte(cap.ConfigStdout), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func mustLiveRow(t *testing.T, rep Report, path string) Row {
	t.Helper()
	for _, r := range rep.Rows {
		if r.Path == path {
			return r
		}
	}
	t.Fatalf("missing %s in %+v", path, rep.Rows)
	return Row{}
}

func TestLiveEqualSecretMatchesUnredactedEngine(t *testing.T) {
	testenv.RequireDocker(t)
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	compose := filepath.Join(dir, "compose.yaml")
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(compose, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	in := mustInternal(t, dir, []string{compose})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "--project-directory", dir, "-f", compose, "config")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose config: %v", err)
	}
	if !strings.Contains(string(out), probe) {
		t.Fatal("live engine dump did not contain the equal secret (cannot verify value-dependent match)")
	}
	eng, err := ParseConfig(string(out))
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured, Version: "v5.4.0"})
	row := mustLiveRow(t, rep, "web:API_TOKEN")
	if row.State != StateMatch || row.Certainty != evidence.Proven || !row.Secret {
		t.Fatalf("equal live secret must MATCH %+v", row)
	}
	assertSecretSafe(t, rep, probe)
}

func TestLiveCaptureWithheldSecretIsUncertain(t *testing.T) {
	testenv.RequireDocker(t)
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	compose := filepath.Join(dir, "compose.yaml")
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(compose, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	in := mustInternal(t, dir, []string{compose})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cap := engineadapter.DefaultRunner().Capture(ctx, engineadapter.Request{ProjectDir: dir, Files: []string{compose}})
	if cap.State != engineadapter.StateCaptured {
		t.Fatalf("engine state=%s detail=%s", cap.State, cap.Detail)
	}
	if strings.Contains(cap.ConfigStdout, probe) {
		t.Fatal("adapter capture leaked raw secret")
	}
	eng, err := ParseConfig(cap.ConfigStdout)
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: cap.State, Version: cap.Version})
	row := mustLiveRow(t, rep, "web:API_TOKEN")
	if row.State != StateUncertain || row.Certainty != evidence.Unknown || !row.Secret {
		t.Fatalf("adapter-withheld engine secret must be uncertain %+v", row)
	}
	assertSecretSafe(t, rep, probe)
}

func TestLiveDriveLetterOverlayDifferentialMatch(t *testing.T) {
	testenv.RequireDocker(t)
	dir := t.TempDir()
	base := filepath.Join(dir, "compose.yaml")
	over := filepath.Join(dir, "overlay.yaml")
	if err := os.WriteFile(base, []byte("services:\n  web:\n    image: alpine\n    volumes:\n      - 'C:\\Alpha:/data'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(over, []byte("services:\n  web:\n    volumes:\n      - 'D:\\Beta:/data'\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	in := mustInternal(t, dir, []string{base, over})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cap := engineadapter.DefaultRunner().Capture(ctx, engineadapter.Request{ProjectDir: dir, Files: []string{base, over}})
	if cap.State != engineadapter.StateCaptured {
		t.Fatalf("engine state=%s detail=%s", cap.State, cap.Detail)
	}
	eng, err := ParseConfig(cap.ConfigStdout)
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: cap.State, Version: cap.Version})
	row := mustLiveRow(t, rep, "services.web.volumes")
	if row.State != StateMatch {
		t.Fatalf("drive-letter overlay volumes must MATCH %+v", row)
	}
	if strings.Contains(row.Internal, "Alpha") || strings.Contains(row.Engine, "Alpha") {
		t.Fatalf("stale C:\\Alpha still visible %+v", row)
	}
}
