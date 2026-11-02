// SPDX-License-Identifier: Apache-2.0

package extends

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/merge"
)

func loadExtendsFixture(t *testing.T, rel string) *composeparse.Document {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "extends", filepath.FromSlash(rel))
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
	return d
}

func TestOfficialSameFileFixture(t *testing.T) {
	m := map[string]merge.Field{}
	r := Apply(loadExtendsFixture(t, "same-file/compose.yaml"), DiskLoad, nil)
	for _, f := range merge.Documents([]*composeparse.Document{r.Doc}, nil) {
		m[f.Path] = f
	}
	if m["services.cli.image"].Value != "busybox" || m["services.cli.environment.PORT"].Value != "8080" {
		t.Fatalf("%+v", m)
	}
}

func TestOfficialCrossFileFixture(t *testing.T) {
	r := Apply(loadExtendsFixture(t, "cross-file/compose.yaml"), DiskLoad, nil)
	m := map[string]merge.Field{}
	for _, f := range merge.Documents([]*composeparse.Document{r.Doc}, nil) {
		m[f.Path] = f
	}
	if m["services.web.image"].Value != "alpine" || m["services.web.hostname"].Value != "from-file" {
		t.Fatalf("%+v", m)
	}
}

func TestOfficialRelationshipFixture(t *testing.T) {
	r := Apply(loadExtendsFixture(t, "relationship/compose.yaml"), DiskLoad, nil)
	m := map[string]merge.Field{}
	for _, f := range merge.Documents([]*composeparse.Document{r.Doc}, nil) {
		m[f.Path] = f
	}
	if _, ok := m["services.cli.depends_on"]; ok {
		t.Fatal("depends_on inherited")
	}
}

func TestOfficialCycleFixture(t *testing.T) {
	done := make(chan Result, 1)
	go func() {
		done <- Apply(loadExtendsFixture(t, "cycle/compose.yaml"), DiskLoad, nil)
	}()
	select {
	case r := <-done:
		if r.Graph == nil || !r.Graph.HasCycle {
			t.Fatalf("%+v", r.Graph)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fixture cycle hung")
	}
}

func TestOfficialShortFormFixture(t *testing.T) {
	r := Apply(loadExtendsFixture(t, "short-form/compose.yaml"), DiskLoad, nil)
	found := false
	for _, ref := range r.Graph.Refs {
		if ref.Name == "cli" && ref.State == StateUnsupported {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", r.Graph)
	}
}
