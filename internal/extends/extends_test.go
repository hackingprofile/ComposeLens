// SPDX-License-Identifier: Apache-2.0

package extends

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

func fieldsOf(t *testing.T, doc *composeparse.Document) map[string]merge.Field {
	t.Helper()
	r := Apply(doc, DiskLoad, nil)
	out := map[string]merge.Field{}
	for _, f := range merge.Documents([]*composeparse.Document{r.Doc}, nil) {
		out[f.Path] = f
	}
	return out
}

func TestSameFileExtendsAndOverride(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "" +
			"services:\n" +
			"  common:\n" +
			"    image: busybox\n" +
			"    hostname: from-base\n" +
			"    environment:\n" +
			"      TZ: utc\n" +
			"      PORT: \"80\"\n" +
			"  cli:\n" +
			"    extends:\n" +
			"      service: common\n" +
			"    environment:\n" +
			"      PORT: \"8080\"\n",
	})
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if m["services.cli.image"].Value != "busybox" {
		t.Fatalf("image %+v", m["services.cli.image"])
	}
	if m["services.cli.hostname"].Value != "from-base" {
		t.Fatalf("hostname %+v", m["services.cli.hostname"])
	}
	if m["services.cli.environment.TZ"].Value != "utc" {
		t.Fatalf("TZ %+v", m["services.cli.environment.TZ"])
	}
	if m["services.cli.environment.PORT"].Value != "8080" {
		t.Fatalf("PORT %+v", m["services.cli.environment.PORT"])
	}
	r := Apply(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	found := false
	for _, f := range r.Fields {
		if f.Path == "services.cli.image" && f.Origin == OriginInherited {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inherited image %+v", r.Fields)
	}
}

func TestCrossFileExtends(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"base.yaml":    "services:\n  web:\n    image: nginx\n    hostname: from-file\n",
		"compose.yaml": "services:\n  web:\n    extends:\n      file: base.yaml\n      service: web\n    image: alpine\n",
	})
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if m["services.web.image"].Value != "alpine" {
		t.Fatalf("image %+v", m["services.web.image"])
	}
	if m["services.web.hostname"].Value != "from-file" {
		t.Fatalf("hostname %+v", m["services.web.hostname"])
	}
}

func TestRelationshipKeysNotInherited(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "" +
			"services:\n" +
			"  db:\n" +
			"    image: postgres\n" +
			"  common:\n" +
			"    image: busybox\n" +
			"    depends_on: [db]\n" +
			"    container_name: base-name\n" +
			"  cli:\n" +
			"    extends:\n" +
			"      service: common\n" +
			"    hostname: local\n",
	})
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if _, ok := m["services.cli.depends_on"]; ok {
		t.Fatalf("depends_on was inherited %+v", m["services.cli.depends_on"])
	}
	if _, ok := m["services.cli.container_name"]; ok {
		t.Fatalf("container_name was inherited")
	}
	if m["services.cli.image"].Value != "busybox" {
		t.Fatalf("image %+v", m["services.cli.image"])
	}
	r := Apply(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	var cli Ref
	for _, ref := range r.Graph.Refs {
		if ref.Name == "cli" {
			cli = ref
		}
	}
	joined := strings.Join(cli.Excluded, ",")
	if !strings.Contains(joined, "depends_on") || !strings.Contains(joined, "container_name") {
		t.Fatalf("excluded %v", cli.Excluded)
	}
}

func TestCycleIsTypedNotHang(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "" +
			"services:\n" +
			"  a:\n" +
			"    extends:\n" +
			"      service: b\n" +
			"    image: a\n" +
			"  b:\n" +
			"    extends:\n" +
			"      service: a\n" +
			"    image: b\n",
	})
	done := make(chan Result, 1)
	go func() {
		done <- Apply(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	}()
	select {
	case r := <-done:
		if r.Graph == nil || !r.Graph.HasCycle {
			t.Fatalf("expected cycle %+v", r.Graph)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("extends cycle hung")
	}
}

func TestShortFormUnsupported(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  common:\n    image: busybox\n  cli:\n    extends: common\n    hostname: local\n",
	})
	r := Apply(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	var cli Ref
	for _, ref := range r.Graph.Refs {
		if ref.Name == "cli" {
			cli = ref
		}
	}
	if cli.State != StateUnsupported || cli.Form != FormShort {
		t.Fatalf("%+v", cli)
	}
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	if _, ok := m["services.cli.image"]; ok {
		t.Fatalf("short form must not invent inheritance %+v", m["services.cli.image"])
	}
	if m["services.cli.hostname"].Value != "local" {
		t.Fatalf("hostname %+v", m["services.cli.hostname"])
	}
}

func TestExtendsChainIsChildThenBaseNotLooped(t *testing.T) {
	bodies := []string{
		"services:\n  common:\n    image: busybox\n  cli:\n    extends:\n      service: common\n    hostname: local\n",
		"services:\n  cli:\n    extends:\n      service: common\n    hostname: local\n  common:\n    image: busybox\n",
	}
	for i, body := range bodies {
		dir := writeTree(t, map[string]string{"compose.yaml": body})
		r := Apply(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
		var img Field
		for _, f := range r.Fields {
			if f.Path == "services.cli.image" {
				img = f
			}
		}
		if img.Origin != OriginInherited || img.BaseService != "common" {
			t.Fatalf("%d origin %+v", i, img)
		}
		if len(img.Chain) != 2 || !strings.HasSuffix(img.Chain[0], "::cli") || !strings.HasSuffix(img.Chain[1], "::common") {
			t.Fatalf("%d chain %v", i, img.Chain)
		}
	}
}

func TestMissingTargetAbsent(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  cli:\n    extends:\n      service: missing\n    image: alpine\n",
	})
	r := Apply(parseFile(t, filepath.Join(dir, "compose.yaml")), DiskLoad, nil)
	found := false
	for _, ref := range r.Graph.Refs {
		if ref.Name == "cli" && ref.State == StateAbsent {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", r.Graph)
	}
}

func TestSequenceConcatPorts(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "" +
			"services:\n" +
			"  common:\n" +
			"    image: busybox\n" +
			"    ports: [\"80:80\"]\n" +
			"  cli:\n" +
			"    extends:\n" +
			"      service: common\n" +
			"    ports: [\"443:443\"]\n",
	})
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	ports := m["services.cli.ports"]
	if ports.Value != "[80:80, 443:443]" {
		t.Fatalf("ports %+v", ports)
	}
}

func TestSecretInsideExtendedBase(t *testing.T) {
	secret := "synthetic-merge-token-overlay"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  common:\n    image: busybox\n    environment:\n      API_TOKEN: " + secret + "\n  cli:\n    extends:\n      service: common\n    hostname: local\n",
	})
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	tok := m["services.cli.environment.API_TOKEN"]
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

func TestExtendsDriveLetterVolumeDedup(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "" +
			"services:\n" +
			"  common:\n" +
			"    image: alpine\n" +
			"    volumes:\n" +
			"      - 'C:\\Alpha:/data'\n" +
			"  cli:\n" +
			"    extends:\n" +
			"      service: common\n" +
			"    volumes:\n" +
			"      - 'D:\\Beta:/data'\n",
	})
	m := fieldsOf(t, parseFile(t, filepath.Join(dir, "compose.yaml")))
	v := m["services.cli.volumes"]
	if strings.Contains(v.Value, "Alpha") {
		t.Fatalf("extends must dedup drive-letter volumes by target %+v", v)
	}
	if !strings.Contains(v.Value, "Beta") {
		t.Fatalf("child volume missing %+v", v)
	}
}
