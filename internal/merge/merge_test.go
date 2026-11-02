// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/interp"
	"composelens/internal/redact"
)

func docsFrom(t *testing.T, pairs ...string) []*composeparse.Document {
	t.Helper()
	var out []*composeparse.Document
	for i := 0; i+1 < len(pairs); i += 2 {
		d, err := composeparse.Parse(discover.File{Path: pairs[i], Bytes: []byte(pairs[i+1]), Origin: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func byPath(fields []Field) map[string]Field {
	m := map[string]Field{}
	for _, f := range fields {
		m[f.Path] = f
	}
	return m
}

func TestScalarOverride(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    image: nginx\n    hostname: old\n",
		"over.yaml", "services:\n  web:\n    image: redis\n",
	), nil)
	m := byPath(fields)
	img := m["services.web.image"]
	if img.Value != "redis" || img.Action != ActionOverride || !strings.HasSuffix(img.Winner, "over.yaml") {
		t.Fatalf("image %+v", img)
	}
	if len(img.Overridden) != 1 || img.Overridden[0].Value != "nginx" {
		t.Fatalf("overridden %+v", img.Overridden)
	}
	host := m["services.web.hostname"]
	if host.Value != "old" || !strings.HasSuffix(host.Winner, "base.yaml") {
		t.Fatalf("hostname kept %+v", host)
	}
}

func TestMapDeepMerge(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    environment:\n      A: one\n      B: two\n",
		"over.yaml", "services:\n  web:\n    environment:\n      B: two-b\n      C: three\n",
	), nil)
	m := byPath(fields)
	if m["services.web.environment.A"].Value != "one" {
		t.Fatalf("A %+v", m["services.web.environment.A"])
	}
	b := m["services.web.environment.B"]
	if b.Value != "two-b" || b.Action != ActionOverride || len(b.Overridden) == 0 || b.Overridden[0].Value != "two" {
		t.Fatalf("B %+v", b)
	}
	c := m["services.web.environment.C"]
	if c.Value != "three" || c.Action != ActionAdd {
		t.Fatalf("C %+v", c)
	}
}

func TestPortsAppendDistinct(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    ports:\n      - \"8080:80\"\n",
		"over.yaml", "services:\n  web:\n    ports:\n      - \"9090:80\"\n",
	), nil)
	p := byPath(fields)["services.web.ports"]
	if p.Value != "[8080:80, 9090:80]" || p.Action != ActionAppend {
		t.Fatalf("ports %+v", p)
	}
	if p.Certainty != "proven" {
		t.Fatalf("certainty %s", p.Certainty)
	}
}

func TestPortsUniqueKeyDedup(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    ports:\n      - \"8080:80\"\n",
		"over.yaml", "services:\n  web:\n    ports:\n      - \"8080:80\"\n",
	), nil)
	p := byPath(fields)["services.web.ports"]
	if p.Value != "[8080:80]" || p.Action != ActionAppend {
		t.Fatalf("ports %+v", p)
	}
}

func TestDnsAppend(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    dns:\n      - 1.1.1.1\n",
		"over.yaml", "services:\n  web:\n    dns:\n      - 8.8.8.8\n",
	), nil)
	d := byPath(fields)["services.web.dns"]
	if d.Value != "[1.1.1.1, 8.8.8.8]" || d.Action != ActionAppend {
		t.Fatalf("dns %+v", d)
	}
}

func TestCommandAtomicReplace(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    command: [\"echo\", \"base\"]\n",
		"over.yaml", "services:\n  web:\n    command: [\"echo\", \"over\"]\n",
	), nil)
	c := byPath(fields)["services.web.command"]
	if c.Value != "[echo, over]" || c.Action != ActionReplace {
		t.Fatalf("command %+v", c)
	}
	if strings.Contains(c.Value, "base") {
		t.Fatal("command appended")
	}
}

func TestVolumesSameTargetDedup(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    volumes:\n      - ./a:/data\n",
		"over.yaml", "services:\n  web:\n    volumes:\n      - ./b:/data\n",
	), nil)
	v := byPath(fields)["services.web.volumes"]
	if v.Value != "[./b:/data]" || v.Action != ActionAppend {
		t.Fatalf("volumes %+v", v)
	}
}

func TestVolumesDriveLetterSameTargetDedup(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    volumes:\n      - 'C:\\Alpha:/data'\n",
		"over.yaml", "services:\n  web:\n    volumes:\n      - 'D:\\Beta:/data'\n",
	), nil)
	v := byPath(fields)["services.web.volumes"]
	if strings.Contains(v.Value, "Alpha") {
		t.Fatalf("stale drive-letter source kept %+v", v)
	}
	if !strings.Contains(v.Value, `D:\Beta:/data`) && !strings.Contains(v.Value, `D:\\Beta:/data`) {
		t.Fatalf("overlay source missing %+v", v)
	}
	if strings.Count(v.Value, "/data") != 1 && strings.Contains(v.Value, "Alpha") {
		t.Fatalf("not deduped %+v", v)
	}
}

func TestVolumesDriveLetterDifferentTargetsKept(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    volumes:\n      - 'C:\\Alpha:/data'\n",
		"over.yaml", "services:\n  web:\n    volumes:\n      - 'D:\\Beta:/other'\n",
	), nil)
	v := byPath(fields)["services.web.volumes"]
	if !strings.Contains(v.Value, "Alpha") || !strings.Contains(v.Value, "Beta") {
		t.Fatalf("different targets must both be kept %+v", v)
	}
}

func TestVolumesModeSuffixDoesNotCorruptTarget(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    volumes:\n      - 'C:\\Alpha:/data:ro'\n",
		"over.yaml", "services:\n  web:\n    volumes:\n      - 'D:\\Beta:/data:rw'\n",
	), nil)
	v := byPath(fields)["services.web.volumes"]
	if strings.Contains(v.Value, "Alpha") {
		t.Fatalf("mode suffix must still dedup by /data %+v", v)
	}
	if !strings.Contains(v.Value, "Beta") {
		t.Fatalf("overlay missing %+v", v)
	}
}

func TestVolumesLongSyntaxTargetUnchanged(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    volumes:\n      - type: bind\n        source: ./a\n        target: /data\n",
		"over.yaml", "services:\n  web:\n    volumes:\n      - type: bind\n        source: ./b\n        target: /data\n",
	), nil)
	v := byPath(fields)["services.web.volumes"]
	if strings.Contains(v.Value, "./a") || strings.Contains(v.Value, "source: ./a") {
		t.Fatalf("long-form same target should overlay %+v", v)
	}
	if !strings.Contains(v.Value, "./b") && !strings.Contains(v.Value, "b") {
		t.Fatalf("overlay long source missing %+v", v)
	}
}

func TestSecretInAppendedList(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    dns:\n      - 1.1.1.1\n",
		"over.yaml", "services:\n  web:\n    dns:\n      - "+probe+"\n",
	), nil)
	d := byPath(fields)["services.web.dns"]
	if !d.Secret {
		t.Fatalf("list secret %+v", d)
	}
	found := false
	for _, f := range SecretFragments(fields) {
		if strings.Contains(f, probe) {
			found = true
		}
	}
	if !found {
		t.Fatal("probe missing from SecretFragments")
	}
}

func TestResetTag(t *testing.T) {
	d := docsFrom(t,
		"base.yaml", "services:\n  web:\n    environment:\n      A: one\n",
		"over.yaml", "services:\n  web:\n    environment: !reset {}\n",
	)
	env := findPath(d[1].Root, "services", "web", "environment")
	if tag := customTag(env); tag != TagReset {
		t.Fatalf("!reset tag unavailable in yaml.v3: tag=%q node=%+v", tag, env)
	}
	m := byPath(Documents(d, nil))
	got := m["services.web.environment"]
	if got.Action != ActionReset || got.Value != "" {
		t.Fatalf("reset %+v keys=%v", got, keysOf(m))
	}
	if _, ok := m["services.web.environment.A"]; ok {
		t.Fatal("reset should drop children")
	}
}

func TestOverrideTagReplacesMapping(t *testing.T) {
	d := docsFrom(t,
		"base.yaml", "services:\n  web:\n    environment:\n      A: one\n      B: two\n",
		"over.yaml", "services:\n  web:\n    environment: !override\n      C: only\n",
	)
	env := findPath(d[1].Root, "services", "web", "environment")
	if tag := customTag(env); tag != TagOverride {
		t.Fatalf("!override tag unavailable in yaml.v3: tag=%q", tag)
	}
	m := byPath(Documents(d, nil))
	if _, ok := m["services.web.environment.A"]; ok {
		t.Fatal("override should drop A")
	}
	c := m["services.web.environment.C"]
	if c.Value != "only" {
		t.Fatalf("C %+v keys=%v", c, keysOf(m))
	}
}

func TestThreeFileOrdering(t *testing.T) {
	fields := Documents(docsFrom(t,
		"a.yaml", "services:\n  web:\n    image: one\n",
		"b.yaml", "services:\n  web:\n    image: two\n",
		"c.yaml", "services:\n  web:\n    image: three\n",
	), nil)
	img := byPath(fields)["services.web.image"]
	if img.Value != "three" || !strings.HasSuffix(img.Winner, "c.yaml") {
		t.Fatalf("%+v", img)
	}
	if len(img.Overridden) != 2 || img.Overridden[0].Value != "one" || img.Overridden[1].Value != "two" {
		t.Fatalf("order %+v", img.Overridden)
	}
}

func TestInterpolateThenMerge(t *testing.T) {
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := interp.Load(t.TempDir(), nil, t.TempDir(), []string{"IMAGE=redis:lab", "KEEP=from-shell"}, fp)
	if err != nil {
		t.Fatal(err)
	}
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    image: ${IMAGE}\n    hostname: ${KEEP}\n",
		"over.yaml", "services:\n  web:\n    image: nginx\n",
	), tbl)
	m := byPath(fields)
	if m["services.web.image"].Value != "nginx" {
		t.Fatalf("image after interp+merge %+v", m["services.web.image"])
	}
	if m["services.web.hostname"].Value != "from-shell" {
		t.Fatalf("hostname interpolated then kept %+v", m["services.web.hostname"])
	}
}

func TestDocumentsDoesNotReinterpolateEscapedLiteral(t *testing.T) {
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	tbl, err := interp.Load(t.TempDir(), nil, t.TempDir(), []string{"VAR=should-not-apply", "HOME=should-not-apply"}, fp)
	if err != nil {
		t.Fatal(err)
	}
	docs := docsFrom(t, "compose.yaml", "services:\n  web:\n    image: alpine\n    environment:\n      LITERAL: $$VAR\n      MIXED: pre-$$HOME-post\n")
	for _, d := range docs {
		interp.InterpolateTree(d.Root, tbl)
		d.Interpolated = true
	}
	m := byPath(Documents(docs, tbl))
	if m["services.web.environment.LITERAL"].Value != "$VAR" {
		t.Fatalf("LITERAL %+v", m["services.web.environment.LITERAL"])
	}
	if m["services.web.environment.MIXED"].Value != "pre-$HOME-post" {
		t.Fatalf("MIXED %+v", m["services.web.environment.MIXED"])
	}
}

func TestSecretThroughMerge(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    environment:\n      API_TOKEN: synthetic-merge-token-value\n      A: keep\n",
		"over.yaml", "services:\n  web:\n    environment:\n      API_TOKEN: synthetic-merge-token-overlay\n",
	), nil)
	tok := byPath(fields)["services.web.environment.API_TOKEN"]
	if !tok.Secret || tok.Value != "synthetic-merge-token-overlay" {
		t.Fatalf("token %+v", tok)
	}
	frags := SecretFragments(fields)
	found := false
	for _, f := range frags {
		if strings.Contains(f, "synthetic-merge-token-overlay") || strings.Contains(f, "synthetic-merge-token-value") {
			found = true
		}
	}
	if !found {
		t.Fatalf("fragments %v", frags)
	}
}

func TestDottedServiceIdentity(t *testing.T) {
	fields := Documents(docsFrom(t, "compose.yaml", "services:\n  web.api:\n    image: nginx:1.25\n    environment:\n      FOO: bar\n"), nil)
	img := byPath(fields)["services.web.api.image"]
	if img.Service != "web.api" || img.Value != "nginx:1.25" {
		t.Fatalf("%+v", img)
	}
	names := ServiceNames(fields)
	if len(names) != 1 || names[0] != "web.api" {
		t.Fatalf("names %v", names)
	}
	coll := Documents(docsFrom(t, "compose.yaml", "services:\n  web:\n    image: alpine\n  web.api:\n    image: nginx\n"), nil)
	got := ServiceNames(coll)
	if len(got) != 2 || got[0] != "web" || got[1] != "web.api" {
		t.Fatalf("collision names %v", got)
	}
	if byPath(coll)["services.web.image"].Service != "web" {
		t.Fatal("web")
	}
	if byPath(coll)["services.web.api.image"].Service != "web.api" {
		t.Fatal("web.api")
	}
}

func keysOf(m map[string]Field) []string {
	var k []string
	for p := range m {
		k = append(k, p)
	}
	return k
}

func findPath(n *yaml.Node, keys ...string) *yaml.Node {
	n = deref(n)
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = deref(n.Content[0])
	}
	for _, key := range keys {
		if n == nil || n.Kind != yaml.MappingNode {
			return nil
		}
		var next *yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := deref(n.Content[i])
			if k != nil && k.Value == key {
				next = deref(n.Content[i+1])
			}
		}
		n = next
	}
	return n
}
