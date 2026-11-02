// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestEmbeddedReportSchemaIDAndSync(t *testing.T) {
	raw := EmbeddedReportSchema()
	if len(raw) == 0 {
		t.Fatal("embedded schema empty")
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["$id"] != Schema {
		t.Fatalf("$id=%v want %s", obj["$id"], Schema)
	}
	disk, err := os.ReadFile(filepath.Join("..", "..", "schemas", "composelens.report.v0.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, disk) {
		t.Fatal("embedded schema drifted from schemas/composelens.report.v0.json")
	}
}

func TestReportProductionNoRuntimeExternalIO(t *testing.T) {
	ents, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range ents {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		f, err := parser.ParseFile(fset, name, src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			switch path {
			case "net/http", "net/http/httptest":
				t.Fatalf("%s imports %s — report path must stay offline", name, path)
			case "os":
				t.Fatalf("%s imports os — report generation must not read repo files at runtime", name)
			}
		}
		if bytes.Contains(src, []byte("os.ReadFile")) || bytes.Contains(src, []byte("os.Open(")) {
			t.Fatalf("%s contains os file IO", name)
		}
	}
}

func TestReportHTMLWithoutSchemasDir(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBytes(raw); err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(page, []byte("<!DOCTYPE html>")) {
		t.Fatal("expected HTML")
	}
}
