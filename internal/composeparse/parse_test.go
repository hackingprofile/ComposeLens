// SPDX-License-Identifier: Apache-2.0

package composeparse

import (
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/discover"
)

func loadFixture(t *testing.T, name string) discover.File {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "yaml", name)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	return discover.File{Path: abs, Bytes: raw, Origin: "fixture"}
}

func TestSimpleServicesLocations(t *testing.T) {
	doc, err := Parse(loadFixture(t, "simple.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 2 {
		t.Fatalf("services=%d", len(doc.Services))
	}
	if doc.Services[0].Name != "web" || doc.Services[0].Location.Line != 2 {
		t.Fatalf("web: %+v", doc.Services[0])
	}
	if doc.Services[1].Name != "db" || doc.Services[1].Location.Line != 4 {
		t.Fatalf("db: %+v", doc.Services[1])
	}
	if doc.Services[0].Location.Column < 1 {
		t.Fatal("column missing")
	}
}

func TestAnchorsAliasesAndMergeSurvive(t *testing.T) {
	doc, err := Parse(loadFixture(t, "anchors.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 2 {
		t.Fatalf("services=%d", len(doc.Services))
	}
	if doc.Services[0].Name != "web" || doc.Services[0].Location.Line != 6 {
		t.Fatalf("web: %+v", doc.Services[0])
	}
	if doc.Services[1].Name != "worker" || doc.Services[1].Location.Line != 9 {
		t.Fatalf("worker: %+v", doc.Services[1])
	}
}

func TestJSONCompose(t *testing.T) {
	doc, err := Parse(loadFixture(t, "compose.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(doc.Services) != 1 || doc.Services[0].Name != "api" {
		t.Fatalf("%+v", doc.Services)
	}
	if doc.Services[0].Location.Line < 1 {
		t.Fatal("json line missing")
	}
}
