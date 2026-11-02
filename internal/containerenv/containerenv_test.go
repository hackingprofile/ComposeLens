// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/interp"
	"composelens/internal/merge"
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

func fieldsOf(t *testing.T, dir string) []merge.Field {
	t.Helper()
	p := filepath.Join(dir, "compose.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return merge.Documents([]*composeparse.Document{d}, nil)
}

func mustResolve(t *testing.T, fields []merge.Field, host map[string]string, g interp.Getter) []ServiceEnv {
	t.Helper()
	svcs, err := Resolve(fields, host, g)
	if err != nil {
		t.Fatal(err)
	}
	return svcs
}

func varsOf(svcs []ServiceEnv, svc string) map[string]Variable {
	out := map[string]Variable{}
	for _, s := range svcs {
		if s.Service != svc {
			continue
		}
		for _, v := range s.Vars {
			out[v.Key] = v
		}
	}
	return out
}

func TestEnvironmentOverridesEnvFile(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.env":        "COLOR=from-file\nSHARED=file\n",
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: a.env\n    environment:\n      COLOR: from-compose\n",
	})
	m := varsOf(mustResolve(t, fieldsOf(t, dir), nil, nil), "web")
	if m["COLOR"].Value != "from-compose" || m["COLOR"].Winner.Kind != KindEnvironment {
		t.Fatalf("COLOR %+v", m["COLOR"])
	}
	if len(m["COLOR"].Overridden) == 0 || m["COLOR"].Overridden[0].Kind != KindEnvFile {
		t.Fatalf("losers %+v", m["COLOR"].Overridden)
	}
	if m["SHARED"].Value != "file" || m["SHARED"].Winner.Kind != KindEnvFile {
		t.Fatalf("SHARED %+v", m["SHARED"])
	}
}

func TestEnvFileLaterWins(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.env":        "SHARED=from-a\nONLY_A=a\n",
		"b.env":        "SHARED=from-b\nONLY_B=b\n",
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file:\n      - a.env\n      - b.env\n",
	})
	m := varsOf(mustResolve(t, fieldsOf(t, dir), nil, nil), "web")
	if m["SHARED"].Value != "from-b" {
		t.Fatalf("SHARED %+v", m["SHARED"])
	}
	if len(m["SHARED"].Overridden) != 1 || m["SHARED"].Overridden[0].Value != "from-a" {
		t.Fatalf("losers %+v", m["SHARED"].Overridden)
	}
	if m["ONLY_A"].Value != "a" || m["ONLY_B"].Value != "b" {
		t.Fatalf("%+v", m)
	}
}

func TestShellPassThrough(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      - DEBUG\n      - COLOR=blue\n",
	})
	host := map[string]string{"DEBUG": "from-shell"}
	m := varsOf(mustResolve(t, fieldsOf(t, dir), host, nil), "web")
	if m["DEBUG"].Value != "from-shell" || m["DEBUG"].Winner.Kind != KindHostShell {
		t.Fatalf("DEBUG %+v", m["DEBUG"])
	}
	if m["COLOR"].Value != "blue" || m["COLOR"].Winner.Kind != KindEnvironment {
		t.Fatalf("COLOR %+v", m["COLOR"])
	}
}

func TestPassThroughUnsetsWhenHostMissing(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.env":        "DEBUG=from-file\nKEEP=ok\n",
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: a.env\n    environment:\n      - DEBUG\n",
	})
	m := varsOf(mustResolve(t, fieldsOf(t, dir), map[string]string{}, nil), "web")
	if m["DEBUG"].State != StateUnset {
		t.Fatalf("expected unset %+v", m["DEBUG"])
	}
	if len(m["DEBUG"].Overridden) == 0 || m["DEBUG"].Overridden[0].Value != "from-file" {
		t.Fatalf("losers %+v", m["DEBUG"].Overridden)
	}
	if m["KEEP"].Value != "ok" {
		t.Fatalf("KEEP %+v", m["KEEP"])
	}
}

func TestMultipleSourcesLosersOrdered(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.env":        "COLOR=from-a\n",
		"b.env":        "COLOR=from-b\n",
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file:\n      - a.env\n      - b.env\n    environment:\n      COLOR: from-compose\n",
	})
	m := varsOf(mustResolve(t, fieldsOf(t, dir), nil, nil), "web")
	v := m["COLOR"]
	if v.Value != "from-compose" || v.Winner.Kind != KindEnvironment {
		t.Fatalf("%+v", v)
	}
	if len(v.Overridden) != 2 {
		t.Fatalf("losers %d %+v", len(v.Overridden), v.Overridden)
	}
	if v.Overridden[0].Value != "from-a" || v.Overridden[1].Value != "from-b" {
		t.Fatalf("order %+v", v.Overridden)
	}
}

func TestMissingEnvFileAbsent(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: missing.env\n    environment:\n      COLOR: blue\n",
	})
	svcs := mustResolve(t, fieldsOf(t, dir), nil, nil)
	found := false
	for _, s := range svcs {
		if s.Service != "web" {
			continue
		}
		for _, f := range s.Files {
			if f.State == StateAbsent {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("%+v", svcs)
	}
	m := varsOf(svcs, "web")
	if m["COLOR"].Value != "blue" {
		t.Fatalf("COLOR %+v", m["COLOR"])
	}
}

func TestListAndMapForms(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  map:\n    image: alpine\n    environment:\n      COLOR: red\n  list:\n    image: alpine\n    environment:\n      - COLOR=blue\n",
	})
	svcs := mustResolve(t, fieldsOf(t, dir), nil, nil)
	if varsOf(svcs, "map")["COLOR"].Value != "red" {
		t.Fatalf("map %+v", varsOf(svcs, "map"))
	}
	if varsOf(svcs, "list")["COLOR"].Value != "blue" {
		t.Fatalf("list %+v", varsOf(svcs, "list"))
	}
}

func TestSecretViaEnvironmentAndEnvFile(t *testing.T) {
	secretE := "synthetic-merge-token-overlay"
	secretF := "synthetic-merge-token-value"
	dir := writeTree(t, map[string]string{
		"s.env":        "API_TOKEN=" + secretF + "\n",
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: s.env\n    environment:\n      API_TOKEN: " + secretE + "\n      OTHER: keep\n",
	})
	m := varsOf(mustResolve(t, fieldsOf(t, dir), nil, nil), "web")
	tok := m["API_TOKEN"]
	if !tok.Secret || tok.Value != secretE {
		t.Fatalf("%+v", tok)
	}
	frags := SecretFragments([]ServiceEnv{{Service: "web", Vars: []Variable{tok}}})
	joined := strings.Join(frags, ",")
	if !strings.Contains(joined, secretE) {
		t.Fatalf("fragments %v", frags)
	}
}

func TestEnvFileCommentsQuotesAndUnsetLine(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.env":        "# comment\n\nCOLOR=blue # trailing\nQUOTED=\"hello world\"\nSINGLE='${NOPE}'\nBARE\nEMPTY=\n",
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: a.env\n",
	})
	m := varsOf(mustResolve(t, fieldsOf(t, dir), nil, nil), "web")
	if m["COLOR"].Value != "blue" {
		t.Fatalf("COLOR %+v", m["COLOR"])
	}
	if m["QUOTED"].Value != "hello world" {
		t.Fatalf("QUOTED %+v", m["QUOTED"])
	}
	if m["SINGLE"].Value != "${NOPE}" {
		t.Fatalf("SINGLE %+v", m["SINGLE"])
	}
	if m["EMPTY"].Value != "" || m["EMPTY"].State != StateSet {
		t.Fatalf("EMPTY %+v", m["EMPTY"])
	}
	if m["BARE"].State != StateUnset {
		t.Fatalf("BARE %+v", m["BARE"])
	}
}
