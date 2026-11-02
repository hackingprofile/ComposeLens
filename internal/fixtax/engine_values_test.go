// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"path/filepath"
	"runtime"
	"slices"
	"testing"

	"composelens/internal/differential"
)

// platformBindRows returns the catalog's platform bind-mount rows with the
// engine value each produces on this host, as `docker compose config` prints
// it without the implied create_host_path (Compose v5.4.0 and v5.6.1).
func platformBindRows(t *testing.T, project string) map[string]string {
	t.Helper()
	sep := string(filepath.Separator)
	relBackslash := project + `/.\rel` // Linux and macOS keep ".\rel" as a file name
	if runtime.GOOS == "windows" {
		relBackslash = project + `\rel`
	}
	return map[string]string{
		"platform.paths.drive-backslash": `type=bind source=C:\Windows target=/in`,
		"platform.paths.forward-slash":   `type=bind source=C:/Windows target=/in`,
		"platform.paths.rel-backslash":   "type=bind source=" + relBackslash + " target=/in",
		"platform.paths.rel-slash":       "type=bind source=" + project + sep + "rel target=/in",
		"platform.paths.spaces":          "type=bind source=" + project + sep + "my data target=/in",
	}
}

// The catalog rows hold whichever way the installed Compose prints a short
// bind: without create_host_path (v5.4.0, v5.6.1) or with the implied
// create_host_path=true (v2.40.3 on the Windows runner). An explicit false
// is a real difference.
func TestCatalogBindRowsMatchEveryComposeRelease(t *testing.T) {
	cat, err := LoadCatalog(filepath.Join(fixturesRoot(t), "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(t.TempDir(), "fixtures", "platform", "x")
	rows := platformBindRows(t, project)
	seen := 0
	for _, fx := range cat.Fixtures {
		engine, ok := rows[fx.ID]
		if !ok {
			continue
		}
		seen++
		row := func(v string) CorpusRow {
			return CorpusRow{Project: project, InScope: []differential.Row{
				{Path: "services.web.image", Engine: "alpine"},
				{Path: "services.web.volumes", Engine: v},
			}}
		}
		for _, v := range []string{engine, engine + " create_host_path=true"} {
			if err := matchEngineFields(fx, row(v)); err != nil {
				t.Errorf("%s: %v", fx.ID, err)
			}
		}
		if err := matchEngineFields(fx, row(engine+" create_host_path=false")); err == nil {
			t.Errorf("%s: an explicit create_host_path=false matched", fx.ID)
		}
	}
	if seen != len(rows) {
		t.Errorf("found %d of %d platform bind rows in the catalog", seen, len(rows))
	}
}

// Engine values resolve per operating system: "{sep}" is that system's
// separator, posixValue applies on Linux and macOS, and a backslash is
// never rewritten. Engine values below are the ones Compose printed on
// each system.
func TestEngineValuesFollowTheEngineOnEachSystem(t *testing.T) {
	cat, err := LoadCatalog(filepath.Join(fixturesRoot(t), "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	field := map[string]PathExpect{}
	for _, fx := range cat.Fixtures {
		for _, pe := range fx.Expected.EngineFields {
			if pe.Path == "services.web.volumes" {
				field[fx.ID] = pe
			}
		}
	}
	cases := []struct {
		id, goos, project, engine, never string
	}{
		{"platform.paths.rel-backslash", "linux", "/home/runner/work/x/fixtures/platform/paths-rel-backslash",
			`type=bind source=/home/runner/work/x/fixtures/platform/paths-rel-backslash/.\rel target=/in`,
			"type=bind source=/home/runner/work/x/fixtures/platform/paths-rel-backslash/rel target=/in"},
		{"platform.paths.rel-backslash", "darwin", "/Users/runner/w/fixtures/platform/paths-rel-backslash",
			`type=bind source=/Users/runner/w/fixtures/platform/paths-rel-backslash/.\rel target=/in`, ""},
		{"platform.paths.rel-backslash", "windows", `D:\a\x\fixtures\platform\paths-rel-backslash`,
			`type=bind source=D:\a\x\fixtures\platform\paths-rel-backslash\rel target=/in create_host_path=true`,
			`type=bind source=D:\a\x\fixtures\platform\paths-rel-backslash\.\rel target=/in`},
		{"platform.paths.rel-slash", "linux", "/w/fixtures/platform/paths-rel-slash",
			"type=bind source=/w/fixtures/platform/paths-rel-slash/rel target=/in", ""},
		{"platform.paths.rel-slash", "windows", `D:\w\paths-rel-slash`,
			`type=bind source=D:\w\paths-rel-slash\rel target=/in create_host_path=true`, ""},
		{"platform.paths.spaces", "linux", "/w/paths-spaces",
			"type=bind source=/w/paths-spaces/my data target=/in", ""},
		{"platform.paths.drive-backslash", "linux", "/w/x",
			`type=bind source=C:\Windows target=/in`, ""},
		{"platform.paths.drive-backslash", "windows", `D:\w\x`,
			`type=bind source=C:\Windows target=/in create_host_path=true`, ""},
	}
	for _, c := range cases {
		pe, ok := field[c.id]
		if !ok {
			t.Fatalf("catalog has no volumes field for %s", c.id)
		}
		wants := EngineValues(pe, c.project, c.goos)
		if !slices.Contains(wants, c.engine) {
			t.Errorf("%s on %s: engine %q not among %q", c.id, c.goos, c.engine, wants)
		}
		if c.never != "" && slices.Contains(wants, c.never) {
			t.Errorf("%s on %s: accepts %q, which Compose does not print there", c.id, c.goos, c.never)
		}
	}
}
