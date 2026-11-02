// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"composelens/internal/exitcode"
	"composelens/internal/policy"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

func TestCatalogCompleteAndSecretSafe(t *testing.T) {
	seen := map[string]struct{}{}
	for _, ent := range Catalog() {
		if ent.ID == "" || ent.Message == "" || ent.Remediation == "" || ent.Doc == "" {
			t.Fatalf("incomplete entry %+v", ent)
		}
		if !strings.HasPrefix(ent.Doc, "docs/") {
			t.Fatalf("doc must be an in-repo path: %s", ent.Doc)
		}
		if _, ok := seen[ent.ID]; ok {
			t.Fatalf("duplicate id %s", ent.ID)
		}
		seen[ent.ID] = struct{}{}
		blob := ent.ID + ent.Message + ent.Remediation + ent.Doc
		if redact.LooksLikeSecret(blob) {
			t.Fatalf("catalog text looks like a secret: %s", ent.ID)
		}
	}
}

func TestEmittedKindsAreCatalogued(t *testing.T) {
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	requireKinds(t, "policy.", stringConsts(t, filepath.Join(root, "internal", "policy", "policy.go"), "Kind"))
	requireKinds(t, "redact.", stringConsts(t, filepath.Join(root, "internal", "redact", "load.go"), "Kind"))
	requireKinds(t, "safety.", stringConsts(t, filepath.Join(root, "internal", "safety", "bounds.go"), "Code"))
	for _, id := range []string{
		"exit.internal", "cli.usage", "exit.input", "exit.safety", "exit.unsupported", "exit.assertion",
	} {
		if _, ok := LookupID(id); !ok {
			t.Fatalf("missing %s", id)
		}
	}
	if _, ok := LookupID("policy." + policy.KindUnknownField); !ok {
		t.Fatal("policy.unknown-field")
	}
	if _, ok := LookupID("redact." + redact.KindInvalid); !ok {
		t.Fatal("redact.invalid")
	}
	if _, ok := LookupID("safety." + string(safety.CodeTotalTooLarge)); !ok {
		t.Fatal("safety.input-total-too-large")
	}
}

func TestLookupRoundTrip(t *testing.T) {
	ent, ok := LookupError(&policy.Error{Kind: policy.KindUnknownField, Message: "unknown field x"})
	if !ok || ent.ID != "policy.unknown-field" {
		t.Fatalf("%v %v", ok, ent)
	}
	ent, ok = LookupError(&redact.Error{Kind: redact.KindUnknownField, Message: "unknown field y"})
	if !ok || ent.ID != "redact.unknown-field" {
		t.Fatalf("%v %v", ok, ent)
	}
	ent, ok = LookupError(safety.NewParseError(safety.CodeFileTooLarge, "f", "too big"))
	if !ok || ent.ID != "safety.input-too-large" {
		t.Fatalf("%v %v", ok, ent)
	}
	ent, ok = LookupExit(exitcode.Assertion)
	if !ok || ent.ID != "exit.assertion" {
		t.Fatalf("%v %v", ok, ent)
	}
	ent, ok = LookupExit(exitcode.Usage)
	if !ok || ent.ID != "cli.usage" {
		t.Fatalf("%v %v", ok, ent)
	}
}

func TestGuardFailsWhenKindUncatalogued(t *testing.T) {
	if _, ok := LookupID("policy.not-a-real-kind"); ok {
		t.Fatal("unknown id must not resolve")
	}
	kinds := stringConsts(t, testPolicyPath(t), "Kind")
	if len(kinds) == 0 {
		t.Fatal("parser found no policy kinds — completeness guard is blind")
	}
}

func requireKinds(t *testing.T, prefix string, kinds []string) {
	t.Helper()
	if len(kinds) == 0 {
		t.Fatalf("no kinds extracted for %s", prefix)
	}
	for _, k := range kinds {
		id := prefix + k
		if _, ok := LookupID(id); !ok {
			t.Fatalf("uncatalogued emitted kind %s", id)
		}
	}
}

func testPolicyPath(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	return filepath.Join(filepath.Dir(file), "..", "policy", "policy.go")
}

func stringConsts(t *testing.T, path, namePrefix string) []string {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, d := range f.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if !strings.HasPrefix(name.Name, namePrefix) {
					continue
				}
				if i >= len(vs.Values) {
					continue
				}
				bl, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || bl.Kind != token.STRING {
					continue
				}
				val := strings.Trim(bl.Value, `"`)
				if val != "" {
					out = append(out, val)
				}
			}
		}
	}
	return out
}
