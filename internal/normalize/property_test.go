// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/merge"
)

func TestPropertyFromMergeIdempotent(t *testing.T) {
	docs := []string{
		"services:\n  web:\n    image: alpine\n    ports:\n      - \"8080:80\"\n    volumes:\n      - /data:/data:ro\n    labels:\n      a: b\n    command: [\"sleep\", \"1\"]\n",
		"services:\n  api:\n    image: alpine\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n    environment:\n      APP_ENV: demo\n",
		"services:\n  web.api:\n    image: alpine\n    ports:\n      - target: 80\n        published: 8080\n        protocol: tcp\n",
	}
	for i, raw := range docs {
		d, err := composeparse.Parse(discover.File{Path: "c.yaml", Bytes: []byte(raw), Origin: "t"})
		if err != nil {
			t.Fatalf("%d: %v", i, err)
		}
		fields := merge.Documents([]*composeparse.Document{d}, nil)
		a := FromMerge(fields)
		b := FromMerge(fields)
		if !Equal(a, b) {
			t.Fatalf("%d: FromMerge not idempotent", i)
		}
		if !Equal(a, a) {
			t.Fatal("reflexive")
		}
	}
}

func TestFamilyHelpersCoverDualForm(t *testing.T) {
	d, err := composeparse.Parse(discover.File{Path: "c.yaml", Bytes: []byte("services:\n  web:\n    image: alpine\n    ports:\n      - \"80:80\"\n    volumes:\n      - /a:/b\n    labels:\n      k: v\n    command: [\"x\"]\n    entrypoint: [\"y\"]\n    healthcheck:\n      test: [\"CMD\", \"true\"]\n"), Origin: "t"})
	if err != nil {
		t.Fatal(err)
	}
	m := FromMerge(merge.Documents([]*composeparse.Document{d}, nil))
	s, ok := ServiceByName(m, "web")
	if !ok {
		t.Fatal("web")
	}
	known := []string{"web"}
	for _, path := range []string{"services.web.ports[0]", "services.web.volumes[0]", "services.web.labels.k", "services.web.command[0]", "services.web.entrypoint[0]", "services.web.healthcheck.test[0]"} {
		if !DualFormPath(path, known) {
			t.Fatalf("dual %s", path)
		}
		root, ok := FamilyRoot(path, known)
		if !ok {
			t.Fatalf("root %s", path)
		}
		disp, present, secret := FamilyDisplay(s, root)
		if !present || disp == "" {
			t.Fatalf("display %s %q present=%v", root, disp, present)
		}
		if secret {
			t.Fatalf("secret %s", root)
		}
		if !FamilyEqual(s, s, root) {
			t.Fatalf("equal %s", root)
		}
		if FamilySource(s, root) == "" {
			t.Fatalf("source %s", root)
		}
	}
	if DualFormPath("services.web.image", known) {
		t.Fatal("image is not dual-form")
	}
	if _, ok := FamilyRoot("not-a-path", known); ok {
		t.Fatal("bogus")
	}
	empty := Service{Name: "web"}
	if FamilySource(empty, "services.web.ports") != "" || FamilySource(empty, "services.web.volumes") != "" {
		t.Fatal("empty source")
	}
	if disp, present, _ := FamilyDisplay(empty, "services.web.command"); present || disp != "" {
		t.Fatal("empty command")
	}
	if FamilyEqual(empty, s, "services.web.nope") {
		t.Fatal("unknown family")
	}
}

func TestEqualDetectsServiceMismatch(t *testing.T) {
	a := Model{Services: []Service{{Name: "web"}}}
	b := Model{Services: []Service{{Name: "api"}}}
	if Equal(a, b) || Equal(a, Model{}) {
		t.Fatal("mismatch")
	}
}
