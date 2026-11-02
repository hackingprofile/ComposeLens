// SPDX-License-Identifier: Apache-2.0

package interp

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/redact"
)

func g(pairs ...string) *Table {
	host := map[string]string{}
	for i := 0; i+1 < len(pairs); i += 2 {
		host[pairs[i]] = pairs[i+1]
	}
	return &Table{host: host}
}

func TestGrammarForms(t *testing.T) {
	lookup := g("SET", "value", "EMPTY", "", "IMAGE", "nginx")
	cases := []struct {
		raw, want, state, form string
	}{
		{"$SET", "value", StateResolved, FormBare},
		{"${SET}", "value", StateResolved, FormBrace},
		{"${MISSING:-fallback}", "fallback", StateDefaulted, FormDefaultEmpty},
		{"${EMPTY:-fallback}", "fallback", StateDefaulted, FormDefaultEmpty},
		{"${SET:-fallback}", "value", StateResolved, FormDefaultEmpty},
		{"${MISSING-fallback}", "fallback", StateDefaulted, FormDefaultUnset},
		{"${EMPTY-fallback}", "", StateResolved, FormDefaultUnset},
		{"${SET-fallback}", "value", StateResolved, FormDefaultUnset},
		{"${SET:+yes}", "yes", StateResolved, FormAltNonEmpty},
		{"${EMPTY:+yes}", "", StateAbsentEmpty, FormAltNonEmpty},
		{"${MISSING:+yes}", "", StateAbsentEmpty, FormAltNonEmpty},
		{"${SET+yes}", "yes", StateResolved, FormAltSet},
		{"${EMPTY+yes}", "yes", StateResolved, FormAltSet},
		{"${MISSING+yes}", "", StateAbsentEmpty, FormAltSet},
		{"$$", "$", StateEscapedLiteral, FormEscape},
		{"cost $$5", "cost $5", StateEscapedLiteral, FormMixed},
		{"pre-$SET-post", "pre-value-post", StateResolved, FormBare},
		{"${IMAGE}", "nginx", StateResolved, FormBrace},
	}
	for _, tc := range cases {
		got := Substitute(tc.raw, lookup)
		if got.State == StateRequiredError {
			t.Fatalf("%s: unexpected required-error %s", tc.raw, got.Error)
		}
		if got.Resolved != tc.want || got.State != tc.state {
			t.Fatalf("%s: resolved=%q state=%s want %q %s", tc.raw, got.Resolved, got.State, tc.want, tc.state)
		}
		if tc.form != FormMixed && got.Form != tc.form && got.Form != FormMixed {
			t.Fatalf("%s: form=%s want %s", tc.raw, got.Form, tc.form)
		}
	}
}

func TestRequiredNeverFabricates(t *testing.T) {
	lookup := g("EMPTY", "", "SET", "ok")
	miss := Substitute("${MUST:?missing must}", lookup)
	if miss.State != StateRequiredError || miss.Resolved != "" || miss.Error != "missing must" {
		t.Fatalf("unset required: %+v", miss)
	}
	empty := Substitute("${EMPTY:?missing empty}", lookup)
	if empty.State != StateRequiredError || empty.Resolved != "" {
		t.Fatalf("empty required: %+v", empty)
	}
	ok := Substitute("${SET:?nope}", lookup)
	if ok.State != StateResolved || ok.Resolved != "ok" {
		t.Fatalf("set required: %+v", ok)
	}
	unsetOnly := Substitute("${MUST?missing maybe}", lookup)
	if unsetOnly.State != StateRequiredError || unsetOnly.Resolved != "" {
		t.Fatalf("unset-only required: %+v", unsetOnly)
	}
	emptyOK := Substitute("${EMPTY?missing maybe}", lookup)
	if emptyOK.State != StateResolved || emptyOK.Resolved != "" {
		t.Fatalf("empty allowed for ?: %+v", emptyOK)
	}
}

func TestDollarEscapeNotRecursive(t *testing.T) {
	lookup := g("VAR", "secret-should-not-apply")
	got := Substitute("$$VAR", lookup)
	if got.Resolved != "$VAR" {
		t.Fatalf("got %q", got.Resolved)
	}
	nested := Substitute("${VAR:-$OTHER}", lookup)
	if nested.Resolved != "secret-should-not-apply" {
		t.Fatalf("set var should win: %q", nested.Resolved)
	}
	// Compose expands references inside default text: OTHER is unset here, so
	// the default is empty (docker compose config: "").
	def := Substitute("${MISSING:-$OTHER}", lookup)
	if def.Resolved != "" {
		t.Fatalf("nested default: want empty for unset OTHER, got %q", def.Resolved)
	}
	if got := Substitute("${MISSING:-$OTHER}", g("OTHER", "oth")).Resolved; got != "oth" {
		t.Fatalf("nested default: want oth, got %q", got)
	}
	if got := Substitute("${MISSING:-$$OTHER}", lookup).Resolved; got != "$OTHER" {
		t.Fatalf("escaped dollar inside a default: want literal $OTHER, got %q", got)
	}
	if def.State != StateDefaulted {
		t.Fatalf("state %s", def.State)
	}
}

func TestUnrecognizedDollarUnknownCertainty(t *testing.T) {
	got := Substitute("price $5", g())
	if got.Resolved != "price $5" {
		t.Fatalf("got %q", got.Resolved)
	}
	if got.Certainty != "unknown" {
		t.Fatalf("certainty %s", got.Certainty)
	}
}

func TestInterpolationPrecedence(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("COLOR=from-dotenv\nONLY_DOTENV=dot\nEMPTY=\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	env1 := filepath.Join(dir, "one.env")
	env2 := filepath.Join(dir, "two.env")
	if err := os.WriteFile(env1, []byte("COLOR=from-env1\nFILE1=a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(env2, []byte("COLOR=from-env2\nFILE2=b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Load(dir, nil, dir, []string{"COMPOSE_ENV_FILES=" + env1 + "," + env2, "COLOR=from-shell"}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, src := tbl.Get("COLOR"); !ok || v != "from-shell" || src.Stage != "host-shell" {
		t.Fatalf("shell should win: v=%s ok=%v src=%+v", v, ok, src)
	}
	tbl2, err := Load(dir, []string{env1, env2}, dir, []string{"UNRELATED=1"}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, src := tbl2.Get("COLOR"); !ok || v != "from-env2" || src.Stage != "env-file" {
		t.Fatalf("later env-file should win: v=%s src=%+v", v, src)
	}
	if _, ok, _ := tbl2.Get("ONLY_DOTENV"); ok {
		t.Fatal("--env-file replaces project .env; ONLY_DOTENV must not load from .env")
	}
	if _, ok, _ := tbl2.Get("ABSENT"); ok {
		t.Fatal("absent should be unset")
	}
	got := Substitute("${COLOR}", tbl2)
	if got.Resolved != "from-env2" || got.Source == nil || got.Source.Stage != "env-file" {
		t.Fatalf("subst %+v", got)
	}

	none, err := Load(dir, nil, dir, []string{"UNRELATED=1"}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, src := none.Get("ONLY_DOTENV"); !ok || v != "dot" || src.Stage != "project-env" {
		t.Fatalf("no --env-file must still load .env: v=%s ok=%v src=%+v", v, ok, src)
	}
}

func TestLoadEnvFileReplacesProjectDotenv(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TAG=1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("HOSTV=repro-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}

	noExtra, err := Load(dir, nil, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := noExtra.Get("TAG"); !ok || v != "1.25" {
		t.Fatalf("no --env-file TAG: %s %v", v, ok)
	}
	if _, ok, _ := noExtra.Get("HOSTV"); ok {
		t.Fatal("HOSTV should be unset without extra.env")
	}

	withExtra, err := Load(dir, []string{extra}, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := withExtra.Get("TAG"); ok {
		t.Fatal("TAG only in .env must drop when --env-file is given")
	}
	if v, ok, src := withExtra.Get("HOSTV"); !ok || v != "repro-host" || src.Stage != "env-file" {
		t.Fatalf("HOSTV from --env-file: v=%s ok=%v src=%+v", v, ok, src)
	}

	viaCompose, err := Load(dir, nil, dir, []string{"COMPOSE_ENV_FILES=" + extra}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := viaCompose.Get("TAG"); ok {
		t.Fatal("TAG must drop when COMPOSE_ENV_FILES replaces .env")
	}
	if v, ok, _ := viaCompose.Get("HOSTV"); !ok || v != "repro-host" {
		t.Fatalf("COMPOSE_ENV_FILES HOSTV: %s %v", v, ok)
	}

	shell, err := Load(dir, []string{extra}, dir, []string{"TAG=from-shell"}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, src := shell.Get("TAG"); !ok || v != "from-shell" || src.Stage != "host-shell" {
		t.Fatalf("shell still highest: v=%s src=%+v", v, src)
	}

	missing := filepath.Join(dir, "no-such.env")
	override, err := Load(dir, []string{extra}, dir, []string{"COMPOSE_ENV_FILES=" + missing}, fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := override.Get("TAG"); ok {
		t.Fatal("explicit --env-file must not load predefined TAG")
	}
	if v, ok, _ := override.Get("HOSTV"); !ok || v != "repro-host" {
		t.Fatalf("explicit --env-file HOSTV: %s %v", v, ok)
	}
}

func TestSecretFragmentsCoverInterpolatedValue(t *testing.T) {
	lookup := g("API_TOKEN", "synthetic-interp-token-value")
	got := Substitute("Bearer ${API_TOKEN}", lookup)
	if !got.Secret {
		t.Fatal("expected secret")
	}
	if got.Resolved != "Bearer synthetic-interp-token-value" {
		t.Fatalf("resolved %q", got.Resolved)
	}
	frags := SecretFragments([]Value{got})
	found := false
	for _, f := range frags {
		if strings.Contains(f, "synthetic-interp-token-value") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fragments %v", frags)
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN=synthetic-interp-token-value\nIMAGE=nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := Load(dir, nil, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
	}
	fromFile := Substitute("${API_TOKEN}", tbl)
	if !fromFile.Secret || fromFile.Resolved != "synthetic-interp-token-value" {
		t.Fatalf("load+subst %+v vars=%+v", fromFile, fromFile.Variables)
	}
}
