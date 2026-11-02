// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func fixturesRoot(t *testing.T) string {
	t.Helper()
	p, err := filepath.Abs(filepath.Join("..", "..", "fixtures"))
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCatalogSchemaAndUndeclaredEmpty(t *testing.T) {
	root := fixturesRoot(t)
	cat, err := LoadCatalog(filepath.Join(root, "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if cat.Schema != Schema {
		t.Fatalf("schema %q", cat.Schema)
	}
	missing, err := Undeclared(root, cat)
	if err != nil {
		t.Fatal(err)
	}
	if len(missing) != 0 {
		t.Fatalf("undeclared files: %v", missing)
	}
	required := []string{
		"yaml", "paths", "interpolation", "merge", "profiles", "include", "extends",
		"container-env", "explain", "diff", "check", "graph", "normalization", "secret-safety",
	}
	seen := map[string]bool{}
	for _, fx := range cat.Fixtures {
		seen[fx.Feature] = true
		if fx.Expected.Engine != EnginePending && fx.Expected.Engine != EngineMatched && fx.Expected.Engine != EngineDivergent && fx.Expected.Engine != EngineError {
			t.Fatalf("%s engine %q", fx.ID, fx.Expected.Engine)
		}
	}
	for _, f := range required {
		if !seen[f] {
			t.Fatalf("missing feature %s", f)
		}
	}
}

func TestLoadCatalogRejectsGuessedEngine(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"schema: composelens.fixtax.v0",
		"fixtures:",
		"- id: guessed",
		"  feature: yaml",
		"  kind: baseline",
		"  description: must not guess engine",
		"  provenance: {source: synthetic}",
		"  files: [a.yaml]",
		"  expected:",
		"    engine: nginx:1.27",
		"    local: {assertion: parse-ok}",
		"",
	}, "\n")
	p := filepath.Join(dir, "catalog.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := LoadCatalog(p)
	if err == nil || !strings.Contains(err.Error(), EnginePending) {
		t.Fatalf("want reject guessed engine, got %v", err)
	}
}

func TestCatalogHarness(t *testing.T) {
	root := fixturesRoot(t)
	rep, err := Run(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Undeclared) != 0 {
		t.Fatalf("undeclared %v", rep.Undeclared)
	}
	if rep.Failed != 0 {
		for _, r := range rep.Results {
			if r.Status == StatusFailed {
				t.Errorf("%s: %s", r.ID, r.Detail)
			}
		}
		t.Fatalf("failed=%d", rep.Failed)
	}
	if rep.Total == 0 || rep.Passed+rep.Skipped != rep.Total {
		t.Fatalf("counts total=%d passed=%d skipped=%d failed=%d", rep.Total, rep.Passed, rep.Skipped, rep.Failed)
	}
	if rep.PendingEngine == 0 || rep.PendingEngine >= rep.Total {
		t.Fatalf("pendingEngine=%d total=%d (baseline corpus unpins some rows; others stay pending)", rep.PendingEngine, rep.Total)
	}
	if rep.Schema != Schema {
		t.Fatalf("schema %q", rep.Schema)
	}
	raw, err := EncodeReport(rep)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded["schema"] != Schema {
		t.Fatalf("json schema %v", decoded["schema"])
	}
	for _, key := range []string{"total", "passed", "failed", "skipped", "pendingEngine", "byFeature", "byKind", "results", "undeclared"} {
		if _, ok := decoded[key]; !ok {
			t.Fatalf("missing json key %s", key)
		}
	}
	if _, ok := decoded["undeclared"].([]any); !ok {
		t.Fatalf("undeclared want array, got %T %v", decoded["undeclared"], decoded["undeclared"])
	}
	otherGOOS := "posix"
	if runtime.GOOS != "windows" {
		otherGOOS = "windows"
	}
	sawSkip := false
	for _, r := range rep.Results {
		if r.ID == "paths."+otherGOOS || (otherGOOS == "posix" && r.ID == "paths.posix") || (otherGOOS == "windows" && r.ID == "paths.windows") {
			if r.Status != StatusSkipped {
				t.Fatalf("%s status %s want skipped on GOOS=%s", r.ID, r.Status, runtime.GOOS)
			}
			sawSkip = true
		}
	}
	if !sawSkip {
		t.Fatalf("expected a skipped path fixture for the other GOOS on %s", runtime.GOOS)
	}
	if dir := os.Getenv("COMPOSELENS_FIXTAX_EVIDENCE_DIR"); dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "harness.json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
		cat, err := LoadCatalog(filepath.Join(root, "catalog.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		if err := writeFeatureExamples(filepath.Join(dir, "examples-by-feature.yaml"), cat); err != nil {
			t.Fatal(err)
		}
	}
}

func writeFeatureExamples(path string, cat Catalog) error {
	seen := map[string]bool{}
	out := Catalog{Schema: Schema}
	for _, fx := range cat.Fixtures {
		if seen[fx.Feature] {
			continue
		}
		seen[fx.Feature] = true
		out.Fixtures = append(out.Fixtures, fx)
	}
	raw, err := yaml.Marshal(&out)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o644)
}

func TestGoosMatchesPosix(t *testing.T) {
	if runtime.GOOS == "windows" {
		if goosMatches("posix") {
			t.Fatal("posix must not match windows")
		}
		if !goosMatches("windows") {
			t.Fatal("windows should match")
		}
		return
	}
	if !goosMatches("posix") {
		t.Fatal("posix should match non-windows")
	}
	if goosMatches("windows") {
		t.Fatal("windows must not match this GOOS")
	}
}
