// SPDX-License-Identifier: Apache-2.0

package idpath

import "testing"

func TestParseDotlessUnchanged(t *testing.T) {
	svc, rest, ok := Parse("services.web.image", nil)
	if !ok || svc != "web" || rest != ".image" {
		t.Fatalf("%q %q %v", svc, rest, ok)
	}
	if Join("web", "image") != "services.web.image" {
		t.Fatal(Join("web", "image"))
	}
}

func TestParseDottedNeedsKnown(t *testing.T) {
	svc, rest, ok := Parse("services.web.api.environment.FOO", nil)
	if !ok || svc != "web" || rest != ".api.environment.FOO" {
		t.Fatalf("fallback first-token: %q %q", svc, rest)
	}
	svc, rest, ok = Parse("services.web.api.environment.FOO", []string{"web.api"})
	if !ok || svc != "web.api" || rest != ".environment.FOO" {
		t.Fatalf("known: %q %q", svc, rest)
	}
}

func TestCollisionLongestMatch(t *testing.T) {
	known := []string{"web", "web.api"}
	svc, rest, ok := Parse("services.web.api.image", known)
	if !ok || svc != "web.api" || rest != ".image" {
		t.Fatalf("dotted side %q %q", svc, rest)
	}
	svc, rest, ok = Parse("services.web.image", known)
	if !ok || svc != "web" || rest != ".image" {
		t.Fatalf("dotless side %q %q", svc, rest)
	}
	if Service("services.web.api.ports[0]", known) != "web.api" {
		t.Fatal(Service("services.web.api.ports[0]", known))
	}
}

func TestCollectPrefersExplicit(t *testing.T) {
	got := Collect([]string{"web.api", ""}, []string{"services.web.api.image"})
	if len(got) != 1 || got[0] != "web.api" {
		t.Fatalf("%v", got)
	}
}

func TestEnvOKRejectsDot(t *testing.T) {
	if !EnvOK("FOO_BAR") || EnvOK("FOO.BAR") || EnvOK("1FOO") {
		t.Fatal("env name class")
	}
}
