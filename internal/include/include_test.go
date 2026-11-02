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

func parseFile(t *testing.T, path string) *composeparse.Document {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func mergedFrom(t *testing.T, doc *composeparse.Document) map[string]merge.Field {
	t.Helper()
	r := Expand(doc, DiskLoad, nil)
	fields := merge.Documents(r.Docs, nil)
	m := map[string]merge.Field{}
	for _, f := range fields {
		m[f.Path] = f
	}
	return m
}

func TestShortFormIncludeAndOverride(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    image: included\n    hostname: keep\n",
		"compose.yaml": "include: base.yaml\nservices:\n  web:\n    image: overridden\n",
	})
	m := mergedFrom(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if m["services.web.image"].Value != "overridden" {
		t.Fatalf("image %+v", m["services.web.image"])
	}
	if m["services.web.hostname"].Value != "keep" {
		t.Fatalf("hostname %+v", m["services.web.hostname"])
	}
	if !strings.HasSuffix(m["services.web.image"].Winner, "compose.yaml") {
		t.Fatalf("winner %s", m["services.web.image"].Winner)
	}
}

func TestLongFormPath(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    image: from-long\n",
		"compose.yaml": "include:\n  path: base.yaml\nservices:\n  web:\n    hostname: local\n",
	})
	r := Expand(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	if len(r.Graph.Refs) != 1 || r.Graph.Refs[0].Spec.Form != FormLong || r.Graph.Refs[0].State != StateOK {
		t.Fatalf("%+v", r.Graph.Refs)
	}
	m := mergedFrom(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if m["services.web.image"].Value != "from-long" || m["services.web.hostname"].Value != "local" {
		t.Fatalf("%+v", m)
	}
}

func TestLongFormEnvFileUnsupportedNotGuessed(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    image: base\n",
		"compose.yaml": "include:\n  path: base.yaml\n  env_file: extra.env\n  project_directory: .\nservices:\n  web:\n    hostname: x\n",
	})
	r := Expand(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	if len(r.Graph.Refs) != 1 {
		t.Fatalf("%+v", r.Graph.Refs)
	}
	ref := r.Graph.Refs[0]
	if ref.State != StateOK || ref.Certainty != "unknown" {
		t.Fatalf("expected unknown extras %+v", ref)
	}
	if len(ref.Spec.UnsupportedFields) < 2 {
		t.Fatalf("unsupported %v", ref.Spec.UnsupportedFields)
	}
}

func TestMultipleIncludesOrder(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.yaml":       "services:\n  web:\n    image: one\n    hostname: from-a\n",
		"b.yaml":       "services:\n  web:\n    image: two\n",
		"compose.yaml": "include:\n  - a.yaml\n  - b.yaml\nservices:\n  web:\n    image: three\n",
	})
	m := mergedFrom(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if m["services.web.image"].Value != "three" {
		t.Fatalf("image %+v", m["services.web.image"])
	}
	if m["services.web.hostname"].Value != "from-a" {
		t.Fatalf("hostname %+v", m["services.web.hostname"])
	}
	img := m["services.web.image"]
	if len(img.Overridden) < 2 {
		t.Fatalf("overridden %+v", img.Overridden)
	}
}

func TestNestedInclude(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"inner.yaml":   "services:\n  inner:\n    image: alpine\n",
		"mid.yaml":     "include: inner.yaml\nservices:\n  mid:\n    image: busybox\n",
		"compose.yaml": "include: mid.yaml\nservices:\n  web:\n    image: nginx\n",
	})
	r := Expand(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	if len(r.Graph.Refs) != 1 || r.Graph.Refs[0].Nested == nil || len(r.Graph.Refs[0].Nested.Refs) != 1 {
		t.Fatalf("graph %+v", r.Graph)
	}
	m := mergedFrom(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if m["services.inner.image"].Value != "alpine" || m["services.mid.image"].Value != "busybox" || m["services.web.image"].Value != "nginx" {
		t.Fatalf("%+v", m)
	}
}

func TestCycleIsTypedNotHang(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"a.yaml": "include: b.yaml\nservices:\n  a:\n    image: a\n",
		"b.yaml": "include: a.yaml\nservices:\n  b:\n    image: b\n",
	})
	done := make(chan Result, 1)
	go func() {
		done <- Expand(parseFile(t, filepath.Join(dir, "a.yaml")), DiskLoad, nil)
	}()
	select {
	case r := <-done:
		if !r.Graph.HasCycle {
			t.Fatalf("expected cycle graph %+v", r.Graph)
		}
		found := false
		var walk func(*Graph)
		walk = func(g *Graph) {
			if g == nil {
				return
			}
			for _, ref := range g.Refs {
				if ref.State == StateCycle {
					found = true
				}
				walk(ref.Nested)
			}
		}
		walk(r.Graph)
		if !found {
			t.Fatalf("no cycle ref %+v", r.Graph)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("include cycle hung")
	}
}

func TestIncludeChainProvenance(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    image: included\n",
		"compose.yaml": "include: base.yaml\nservices:\n  web:\n    hostname: local\n",
	})
	doc := parseFile(t, filepath.Join(dir, "compose.yaml"))
	r := Expand(doc, DiskLoad, nil)
	base := parseFile(t, filepath.Join(dir, "base.yaml")).File.Path
	chain := r.Chains[base]
	if len(chain) < 2 {
		t.Fatalf("chain %v", chain)
	}
}

func TestSecretInsideIncludedFile(t *testing.T) {
	secret := "synthetic-merge-token-overlay"
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    environment:\n      API_TOKEN: " + secret + "\n",
		"compose.yaml": "include: base.yaml\nservices:\n  web:\n    image: nginx\n",
	})
	m := mergedFrom(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	tok := m["services.web.environment.API_TOKEN"]
	if !tok.Secret || tok.Value != secret {
		t.Fatalf("%+v", tok)
	}
	frags := merge.SecretFragments([]merge.Field{tok})
	found := false
	for _, f := range frags {
		if strings.Contains(f, secret) {
			found = true
		}
	}
	if !found {
		t.Fatalf("fragments %v", frags)
	}
}

type mapGet map[string]string

func (m mapGet) Get(key string) (string, bool, interp.Source) {
	v, ok := m[key]
	return v, ok, interp.Source{Key: key, Stage: "host-shell"}
}

func TestInterpolatedIncludePath(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    image: from-interpolated-path\n",
		"compose.yaml": "include: ${INC}\nservices:\n  web:\n    hostname: local\n",
	})
	r := Expand(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, mapGet{"INC": "base.yaml"})
	if len(r.Graph.Refs) != 1 || r.Graph.Refs[0].State != StateOK {
		t.Fatalf("%+v", r.Graph)
	}
	fields := merge.Documents(r.Docs, nil)
	found := false
	for _, f := range fields {
		if f.Path == "services.web.image" && f.Value == "from-interpolated-path" {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", fields)
	}
}
