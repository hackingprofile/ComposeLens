// SPDX-License-Identifier: Apache-2.0

package include

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/merge"
)

func loadIncludeFixture(t *testing.T, rel string) *composeparse.Document {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "include", filepath.FromSlash(rel))
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

func mergedFixture(t *testing.T, rel string) map[string]merge.Field {
	t.Helper()
	r := Expand(loadIncludeFixture(t, rel), DiskLoad, nil)
	fields := merge.Documents(r.Docs, nil)
	m := map[string]merge.Field{}
	for _, f := range fields {
		m[f.Path] = f
	}
	return m
}

func TestOfficialShortFixture(t *testing.T) {
	m := mergedFixture(t, "short/compose.yaml")
	if m["services.web.image"].Value != "overridden" || m["services.web.hostname"].Value != "keep" {
		t.Fatalf("%+v", m)
	}
}

func TestOfficialLongFixture(t *testing.T) {
	r := Expand(loadIncludeFixture(t, "long/compose.yaml"), DiskLoad, nil)
	if len(r.Graph.Refs) != 1 || r.Graph.Refs[0].Spec.Form != FormLong || r.Graph.Refs[0].State != StateOK {
		t.Fatalf("%+v", r.Graph)
	}
	m := mergedFixture(t, "long/compose.yaml")
	if m["services.web.image"].Value != "from-long" || m["services.web.hostname"].Value != "local" {
		t.Fatalf("%+v", m)
	}
}

func TestOfficialLongExtrasUnknown(t *testing.T) {
	r := Expand(loadIncludeFixture(t, "long-extras/compose.yaml"), DiskLoad, nil)
	if len(r.Graph.Refs) != 1 || r.Graph.Refs[0].Certainty != "unknown" || len(r.Graph.Refs[0].Spec.UnsupportedFields) < 2 {
		t.Fatalf("%+v", r.Graph.Refs)
	}
}

func TestOfficialMultiFixtureOrder(t *testing.T) {
	m := mergedFixture(t, "multi/compose.yaml")
	if m["services.web.image"].Value != "three" || m["services.web.hostname"].Value != "from-a" {
		t.Fatalf("%+v", m)
	}
}

func TestOfficialNestedFixture(t *testing.T) {
	m := mergedFixture(t, "nested/compose.yaml")
	if m["services.inner.image"].Value != "alpine" || m["services.mid.image"].Value != "busybox" || m["services.web.image"].Value != "nginx" {
		t.Fatalf("%+v", m)
	}
}

func TestOfficialCycleFixtureTyped(t *testing.T) {
	done := make(chan Result, 1)
	go func() {
		done <- Expand(loadIncludeFixture(t, "cycle/a.yaml"), DiskLoad, nil)
	}()
	select {
	case r := <-done:
		if !r.Graph.HasCycle {
			t.Fatalf("expected cycle %+v", r.Graph)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("fixture cycle hung")
	}
}

func TestOfficialOverrideFixture(t *testing.T) {
	m := mergedFixture(t, "override/compose.yaml")
	img := m["services.web.image"]
	if img.Value != "overridden" || !strings.HasSuffix(img.Winner, "compose.yaml") {
		t.Fatalf("image %+v", img)
	}
	if m["services.web.hostname"].Value != "keep" {
		t.Fatalf("hostname %+v", m["services.web.hostname"])
	}
}
