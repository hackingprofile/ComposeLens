// SPDX-License-Identifier: Apache-2.0

package idpath

import (
	"math/rand"
	"strings"
	"testing"
	"testing/quick"
	"unicode"
)

func TestPropertyJoinParseRoundTrip(t *testing.T) {
	cfg := &quick.Config{MaxCount: 256, Rand: rand.New(rand.NewSource(51))}
	fn := func(svc, field string) bool {
		if !ident(svc) {
			return true
		}
		if field != "" && !ident(field) {
			return true
		}
		p := Join(svc, field)
		got, rest, ok := Parse(p, []string{svc})
		if !ok || got != svc {
			return false
		}
		if field == "" {
			return rest == ""
		}
		return rest == "."+field
	}
	if err := quick.Check(fn, cfg); err != nil {
		t.Fatal(err)
	}
}

func TestPropertyDottedCollisionLongest(t *testing.T) {
	known := []string{"web", "web.api"}
	svc, rest, ok := Parse(Join("web.api", "image"), known)
	if !ok || svc != "web.api" || rest != ".image" {
		t.Fatalf("%q %q", svc, rest)
	}
	svc, rest, ok = Parse(Join("web", "image"), known)
	if !ok || svc != "web" || rest != ".image" {
		t.Fatalf("%q %q", svc, rest)
	}
}

func TestCollectInfersWhenExplicitEmpty(t *testing.T) {
	got := Collect(nil, []string{"services.api.image", "not-a-path", "services.api.ports[0]"})
	if len(got) != 1 || got[0] != "api" {
		t.Fatalf("%v", got)
	}
	if Collect([]string{""}, nil) != nil && len(Collect([]string{""}, nil)) != 0 {
		t.Fatalf("%v", Collect([]string{""}, nil))
	}
}

func ident(s string) bool {
	if s == "" || strings.ContainsAny(s, ".[") {
		return false
	}
	for _, r := range s {
		if r > unicode.MaxASCII || (!unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_') {
			return false
		}
	}
	return s[0] != '.'
}
