// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/envsrc"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/redact"
)

func pipelineVars(t *testing.T, dir, name string, environ []string) map[string]Variable {
	t.Helper()
	path := filepath.Join(dir, name)
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	table, err := interp.Load(dir, nil, dir, environ, fp)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "test"})
	if err != nil {
		t.Fatal(err)
	}
	var getter interp.Getter
	if table != nil {
		getter = table
	}
	expanded := include.Expand(doc, include.DiskLoad, getter)
	resolved := make([]*composeparse.Document, 0, len(expanded.Docs))
	for _, d := range expanded.Docs {
		er := extends.Apply(d, extends.DiskLoad, getter)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
	}
	merged := merge.Documents(resolved, table)
	return varsOf(mustResolve(t, merged, envsrc.HostMap(environ), getter), "web")
}

func TestEscapedLiteralCarriesIntoEffectiveEnv(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      LITERAL: $$VAR\n      LITERAL_BRACED: $${notavar}\n      MIXED: pre-$$HOME-post\n",
	})
	m := pipelineVars(t, dir, "compose.yaml", []string{"VAR=should-not-apply", "HOME=should-not-apply", "notavar=should-not-apply"})
	if m["LITERAL"].Value != "$VAR" || m["LITERAL"].State != StateSet {
		t.Fatalf("LITERAL %+v", m["LITERAL"])
	}
	if m["LITERAL_BRACED"].Value != "${notavar}" || m["LITERAL_BRACED"].State != StateSet {
		t.Fatalf("LITERAL_BRACED %+v", m["LITERAL_BRACED"])
	}
	if m["MIXED"].Value != "pre-$HOME-post" || m["MIXED"].State != StateSet {
		t.Fatalf("MIXED %+v", m["MIXED"])
	}
}

func TestUndefinedSingleDollarStaysEmpty(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      GONE: $UNDEFINED\n      GONE_BRACED: ${UNDEFINED}\n      KEEP: ok\n",
	})
	m := pipelineVars(t, dir, "compose.yaml", nil)
	if m["GONE"].Value == "$UNDEFINED" || m["GONE"].Value == "${UNDEFINED}" {
		t.Fatalf("over-corrected GONE into a literal: %+v", m["GONE"])
	}
	if m["GONE_BRACED"].Value == "$UNDEFINED" || m["GONE_BRACED"].Value == "${UNDEFINED}" {
		t.Fatalf("over-corrected GONE_BRACED into a literal: %+v", m["GONE_BRACED"])
	}
	if m["KEEP"].Value != "ok" {
		t.Fatalf("KEEP %+v", m["KEEP"])
	}
}

func TestEscapedSecretStillRedacted(t *testing.T) {
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: $$" + probe + "\n",
	})
	m := pipelineVars(t, dir, "compose.yaml", nil)
	tok := m["API_TOKEN"]
	want := "$" + probe
	if tok.Value != want {
		t.Fatalf("escaped secret value %+v want %q", tok, want)
	}
	if !tok.Secret {
		t.Fatalf("expected secret %+v", tok)
	}
	frags := SecretFragments([]ServiceEnv{{Service: "web", Vars: []Variable{tok}}})
	joined := strings.Join(frags, ",")
	if !strings.Contains(joined, probe) && !strings.Contains(joined, want) {
		t.Fatalf("fragments should include secret material for the guard: %v", frags)
	}
}
