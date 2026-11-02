// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"composelens/internal/differential"
	"composelens/internal/engineadapter"
	"composelens/internal/redact"
	"composelens/internal/safety"
	"composelens/internal/testenv"
)

func TestLiveBaselineCorpus(t *testing.T) {
	testenv.RequireDocker(t)
	root := fixturesRoot(t)
	cat, err := LoadCatalog(filepath.Join(root, "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	matchedInterp, matchedPrec := 0, 0
	var table strings.Builder
	table.WriteString("id\tfeature\texpect\tlive\tpin\tin-scope\n")
	for _, fx := range cat.Fixtures {
		if !EngineAnchored(fx) {
			continue
		}
		// Coverage counts come from the catalog, so a row that disagrees
		// with the installed Compose fails as its own subtest and does not
		// also shrink the count.
		if fx.Expected.Engine == EngineMatched {
			switch fx.Feature {
			case "interpolation":
				matchedInterp++
			case "container-env":
				matchedPrec++
			}
		}
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			for k, v := range fx.Expected.Local.HostEnv {
				t.Setenv(k, v)
			}
			row := RunCorpusFixture(ctx, root, fx, os.Environ())
			if row.Err != "" {
				t.Fatal(row.Err)
			}
			t.Log(EngineNote(fx.Expected.EnginePin, row.LiveVersion))
			fmtLine := fx.ID + "\t" + fx.Feature + "\t" + fx.Expected.Engine + "\t" + row.LiveState + " " + row.LiveVersion + "\t" + fx.Expected.EnginePin + "\t"
			for i, r := range row.InScope {
				if i > 0 {
					fmtLine += "; "
				}
				fmtLine += r.State + " " + r.Path + " cl=" + r.Internal + " eng=" + r.Engine
			}
			if fx.Expected.Engine == EngineError {
				fmtLine += row.LiveState
			}
			fmtLine += "\n"
			table.WriteString(fmtLine)
		})
	}
	if matchedInterp < 8 {
		t.Fatalf("interpolation matched fixtures %d want >=8", matchedInterp)
	}
	if matchedPrec < 6 {
		t.Fatalf("precedence matched fixtures %d want >=6", matchedPrec)
	}
	if dir := os.Getenv("COMPOSELENS_CORPUS_EVIDENCE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "per-fixture-table.txt"), []byte(table.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveRegressionCorpus(t *testing.T) {
	testenv.RequireDocker(t)
	root := fixturesRoot(t)
	cat, err := LoadCatalog(filepath.Join(root, "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var table strings.Builder
	table.WriteString("id\tfeature\texpect\trationale.type\trationale.ref\tlive\tpin\tin-scope\n")
	n := 0
	guards := map[string]bool{
		"merge.regression.ports-append-dedup": false,
		"interpolation.regression.escape":     false,
	}
	for _, fx := range cat.Fixtures {
		if fx.Kind != KindRegression || !EngineAnchored(fx) {
			continue
		}
		n++ // counted from the catalog, whatever the installed Compose prints
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			for k, v := range fx.Expected.Local.HostEnv {
				t.Setenv(k, v)
			}
			row := RunCorpusFixture(ctx, root, fx, os.Environ())
			if row.Err != "" {
				t.Fatal(row.Err)
			}
			t.Log(EngineNote(fx.Expected.EnginePin, row.LiveVersion))
			if fx.Rationale.Type == "" || fx.Rationale.Ref == "" {
				t.Fatal("missing rationale")
			}
			fmtLine := fx.ID + "\t" + fx.Feature + "\t" + fx.Expected.Engine + "\t" + fx.Rationale.Type + "\t" + fx.Rationale.Ref + "\t" + row.LiveState + " " + row.LiveVersion + "\t" + fx.Expected.EnginePin + "\t"
			for i, r := range row.InScope {
				if i > 0 {
					fmtLine += "; "
				}
				fmtLine += r.State + " " + r.Path + " cl=" + r.Internal + " eng=" + r.Engine
			}
			if fx.Expected.Engine == EngineError {
				fmtLine += row.LiveState
			}
			fmtLine += "\n"
			table.WriteString(fmtLine)
			if _, ok := guards[fx.ID]; ok && fx.Expected.Engine == EngineMatched && row.Err == "" {
				guards[fx.ID] = true
			}
		})
	}
	if n < 8 {
		t.Fatalf("regression engine-anchored fixtures %d want >=8", n)
	}
	for id, ok := range guards {
		if !ok {
			t.Fatalf("regression guard %s did not MATCH", id)
		}
	}
	if dir := os.Getenv("COMPOSELENS_REGRESSION_EVIDENCE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "per-fixture-table.txt"), []byte(table.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestLivePlatformCorpus(t *testing.T) {
	testenv.RequireDocker(t)
	root := fixturesRoot(t)
	cat, err := LoadCatalog(filepath.Join(root, "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	var table strings.Builder
	table.WriteString("id\tfeature\tclass\texpect\trationale.type\trationale.ref\tlive\tpin\tin-scope\n")
	n := 0
	classes := map[string]bool{}
	for _, fx := range cat.Fixtures {
		if fx.Kind != KindPlatform || !EngineAnchored(fx) {
			continue
		}
		n++ // counted from the catalog, whatever the installed Compose prints
		class := platformClass(fx.ID)
		classes[class] = true
		fx := fx
		t.Run(fx.ID, func(t *testing.T) {
			for k, v := range fx.Expected.Local.HostEnv {
				t.Setenv(k, v)
			}
			row := RunCorpusFixture(ctx, root, fx, os.Environ())
			if row.Err != "" {
				t.Fatal(row.Err)
			}
			t.Log(EngineNote(fx.Expected.EnginePin, row.LiveVersion))
			if fx.Rationale.Type == "" || fx.Rationale.Ref == "" {
				t.Fatal("missing rationale")
			}
			fmtLine := fx.ID + "\t" + fx.Feature + "\t" + class + "\t" + fx.Expected.Engine + "\t" + fx.Rationale.Type + "\t" + fx.Rationale.Ref + "\t" + row.LiveState + " " + row.LiveVersion + "\t" + fx.Expected.EnginePin + "\t"
			for i, r := range row.InScope {
				if i > 0 {
					fmtLine += "; "
				}
				fmtLine += r.State + " " + r.Path + " cl=" + r.Internal + " eng=" + r.Engine
			}
			if fx.Expected.Engine == EngineError {
				fmtLine += row.LiveState
			}
			fmtLine += "\n"
			table.WriteString(fmtLine)
		})
	}
	if n < 8 {
		t.Fatalf("platform engine-anchored fixtures %d want >=8", n)
	}
	for _, need := range []string{"paths", "newline", "encoding", "shell"} {
		if !classes[need] {
			t.Fatalf("platform corpus missing class %s", need)
		}
	}
	if dir := os.Getenv("COMPOSELENS_PLATFORM_EVIDENCE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "per-fixture-table.txt"), []byte(table.String()), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func platformClass(id string) string {
	switch {
	case strings.Contains(id, ".paths."):
		return "paths"
	case strings.Contains(id, ".newline."):
		return "newline"
	case strings.Contains(id, ".encoding."):
		return "encoding"
	case strings.Contains(id, ".shell."):
		return "shell"
	default:
		return "other"
	}
}

func TestLoadCatalogRejectsPlatformWithoutRationale(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"schema: composelens.fixtax.v0",
		"fixtures:",
		"- id: norat",
		"  feature: paths",
		"  kind: platform",
		"  description: anchored without rationale",
		"  provenance: {source: synthetic}",
		"  files: [a.yaml]",
		"  expected:",
		"    engine: matched",
		"    enginePin: v5.4.0",
		"    engineFields: [{path: services.web.image, value: alpine}]",
		"    local: {assertion: parse-ok}",
		"",
	}, "\n")
	p := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalog(p)
	if err == nil || !strings.Contains(err.Error(), "rationale") {
		t.Fatalf("got %v", err)
	}
}

func TestCorpusSecretProbeInProcess(t *testing.T) {
	testenv.RequireDocker(t)
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	in, err := corpusInternal(dir, []string{filepath.Join(dir, "compose.yaml")}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cap := engineadapter.DefaultRunner().Capture(ctx, engineadapter.Request{ProjectDir: dir, Files: []string{filepath.Join(dir, "compose.yaml")}})
	if cap.State != engineadapter.StateCaptured {
		t.Fatalf("state=%s %s", cap.State, cap.Detail)
	}
	eng, err := differential.ParseConfig(cap.ConfigStdout)
	if err != nil {
		t.Fatal(err)
	}
	rep := differential.CompareInputs(in, eng, differential.Meta{EngineState: cap.State, Version: cap.Version})
	raw := differential.Human(rep)
	if strings.Contains(raw, probe) || strings.Contains(cap.ConfigStdout, probe) {
		t.Fatal("probe leaked")
	}
	if err := safety.Guard([]byte(raw), []string{probe}); err != nil {
		t.Fatal(err)
	}
	_ = redact.MustRedact("API_TOKEN", probe)
}

func TestLoadCatalogRejectsMatchedWithoutPin(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"schema: composelens.fixtax.v0",
		"fixtures:",
		"- id: nopin",
		"  feature: interpolation",
		"  kind: baseline",
		"  description: missing pin",
		"  provenance: {source: synthetic}",
		"  files: [a.yaml]",
		"  expected:",
		"    engine: matched",
		"    engineFields: [{path: services.web.image, value: alpine}]",
		"    local: {assertion: parse-ok}",
		"",
	}, "\n")
	p := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalog(p)
	if err == nil || !strings.Contains(err.Error(), "enginePin") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadCatalogRejectsSecurityWithoutRationale(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"schema: composelens.fixtax.v0",
		"fixtures:",
		"- id: norat",
		"  feature: secret-safety",
		"  kind: security",
		"  description: security row without rationale",
		"  provenance: {source: synthetic}",
		"  files: [a.yaml]",
		"  expected:",
		"    engine: pending-engine",
		"    local: {assertion: parse-ok}",
		"",
	}, "\n")
	p := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalog(p)
	if err == nil || !strings.Contains(err.Error(), "rationale") {
		t.Fatalf("got %v", err)
	}
}

func TestLoadCatalogRejectsRegressionWithoutRationale(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"schema: composelens.fixtax.v0",
		"fixtures:",
		"- id: norat",
		"  feature: merge",
		"  kind: regression",
		"  description: anchored without rationale",
		"  provenance: {source: synthetic}",
		"  files: [a.yaml]",
		"  expected:",
		"    engine: matched",
		"    enginePin: v5.4.0",
		"    engineFields: [{path: services.web.image, value: alpine}]",
		"    local: {assertion: parse-ok}",
		"",
	}, "\n")
	p := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalog(p)
	if err == nil || !strings.Contains(err.Error(), "rationale") {
		t.Fatalf("got %v", err)
	}
}
