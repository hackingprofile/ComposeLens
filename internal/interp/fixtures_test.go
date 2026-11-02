// SPDX-License-Identifier: Apache-2.0

package interp

import (
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/redact"
)

func loadInterpFixture(t *testing.T, name string) *composeparse.Document {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "interpolation", name)
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
	return doc
}

func TestOfficialFixtureForms(t *testing.T) {
	doc := loadInterpFixture(t, "official.yaml")
	tbl := g("IMAGE", "nginx:1.27-alpine", "HOST", "web.local", "ENTRY", "1", "FLAG", "", "MUST", "present", "MAYBE", "")
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	vals := ResolveScalars(composeparse.StringScalars(doc), tbl, fp)
	byPath := map[string]Value{}
	for _, v := range vals {
		byPath[v.Path] = v
	}
	want := map[string]struct{ resolved, state string }{
		"services.official.image":                         {resolved: "nginx:1.27-alpine", state: StateResolved},
		"services.official.hostname":                      {resolved: "web.local", state: StateResolved},
		"services.official.working_dir":                   {resolved: "/app", state: StateDefaulted},
		"services.official.user":                          {resolved: "nobody", state: StateDefaulted},
		"services.official.command[0]":                    {resolved: "start", state: StateResolved},
		"services.official.command[1]":                    {resolved: "on", state: StateResolved},
		"services.official.command[2]":                    {resolved: "$escaped", state: StateEscapedLiteral},
		"services.official.environment.REQUIRED":          {resolved: "present", state: StateResolved},
		"services.official.environment.OPTIONAL_REQUIRED": {resolved: "", state: StateResolved},
		"services.official.environment.LITERAL_DOLLAR":    {resolved: "$VAR", state: StateEscapedLiteral},
	}
	for path, w := range want {
		got, ok := byPath[path]
		if !ok {
			t.Fatalf("missing path %s in %#v", path, byPath)
		}
		if got.Resolved != w.resolved || got.State != w.state {
			t.Fatalf("%s: resolved=%q state=%s want %q %s", path, got.Resolved, got.State, w.resolved, w.state)
		}
	}
}

func TestIssueFixtureEmptyUnsetQuoted(t *testing.T) {
	doc := loadInterpFixture(t, "issues.yaml")
	tbl := g("IMAGE", "nginx", "QUOTED", "quoted-host", "EMPTY", "")
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	vals := ResolveScalars(composeparse.StringScalars(doc), tbl, fp)
	byPath := map[string]Value{}
	for _, v := range vals {
		byPath[v.Path] = v
	}
	if got := byPath["services.issues.image"]; got.Resolved != "pre-nginx-post" {
		t.Fatalf("adjacent: %+v", got)
	}
	if got := byPath["services.issues.hostname"]; got.Resolved != "quoted-host" {
		t.Fatalf("quoted: %+v", got)
	}
	if got := byPath["services.issues.environment.KEEP_EMPTY"]; got.Resolved != "" || got.State != StateResolved {
		t.Fatalf("keep empty: %+v", got)
	}
	if got := byPath["services.issues.environment.FALLBACK_EMPTY"]; got.Resolved != "fallback" || got.State != StateDefaulted {
		t.Fatalf("fallback empty: %+v", got)
	}
	if got := byPath["services.issues.environment.UNSET_DEFAULT"]; got.Resolved != "from-unset" || got.State != StateDefaulted {
		t.Fatalf("unset default: %+v", got)
	}
	// The engine expands $OTHER inside the default; it is unset here.
	if got := byPath["services.issues.environment.NESTED_DEFAULT"]; got.Resolved != "" || got.State != StateDefaulted || len(got.Variables) != 2 {
		t.Fatalf("nested default: %+v", got)
	}
	if _, ok := byPath["services.issues.environment.WINDOWS_STYLE"]; ok {
		t.Fatal("Windows %VAR% is not Compose interpolation and must not be rewritten")
	}
	if got := byPath["services.issues.environment.BARE_UNSET"]; got.State != StateAbsentEmpty || got.Resolved != "" {
		t.Fatalf("bare unset: %+v", got)
	}
	if got := byPath["services.issues.extra_hosts[0]"]; got.Certainty != "unknown" || got.Resolved != "price $5" {
		t.Fatalf("unrecognized dollar: %+v", got)
	}
}

func TestOfficialRequiredErrorFixture(t *testing.T) {
	doc := loadInterpFixture(t, "official.yaml")
	tbl := g("IMAGE", "nginx")
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	vals := ResolveScalars(composeparse.StringScalars(doc), tbl, fp)
	var found bool
	for _, v := range vals {
		if v.Path == "services.official.environment.REQUIRED" {
			found = true
			if v.State != StateRequiredError || v.Resolved != "" || v.Error != "must be set" {
				t.Fatalf("%+v", v)
			}
		}
	}
	if !found {
		t.Fatal("REQUIRED missing")
	}
}
