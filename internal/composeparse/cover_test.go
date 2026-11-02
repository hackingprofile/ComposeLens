// SPDX-License-Identifier: Apache-2.0

package composeparse

import (
	"strings"
	"testing"

	"composelens/internal/discover"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

func TestStringScalarsWalksValuesNotKeys(t *testing.T) {
	d, err := Parse(discover.File{Path: "c.yaml", Bytes: []byte("services:\n  web:\n    image: alpine\n    ports:\n      - \"80\"\n"), Origin: "t"})
	if err != nil {
		t.Fatal(err)
	}
	got := StringScalars(d)
	if len(got) == 0 {
		t.Fatal("no scalars")
	}
	var paths []string
	for _, s := range got {
		paths = append(paths, s.Path+"="+s.Value)
	}
	blob := strings.Join(paths, ",")
	if !strings.Contains(blob, "alpine") || !strings.Contains(blob, "80") {
		t.Fatalf("%s", blob)
	}
	if StringScalars(nil) != nil {
		t.Fatal("nil doc")
	}
}

func TestStringScalarsSkipsNonStringTags(t *testing.T) {
	d, err := Parse(discover.File{Path: "c.yaml", Bytes: []byte("x: true\ny: 3\nz: hello\n"), Origin: "t"})
	if err != nil {
		t.Fatal(err)
	}
	got := StringScalars(d)
	found := false
	for _, s := range got {
		if s.Value == "hello" {
			found = true
		}
		if s.Value == "true" || s.Value == "3" {
			t.Fatalf("non-string scalar leaked: %+v", s)
		}
	}
	if !found {
		t.Fatalf("%+v", got)
	}
}

func TestSafeErrorMessageRedactsSecret(t *testing.T) {
	if SafeErrorMessage(nil) != "" {
		t.Fatal("nil")
	}
	plain := SafeErrorMessage(safety.NewParseError(safety.CodeMalformed, "compose.yaml", "bad indent"))
	if !strings.Contains(plain, "bad indent") {
		t.Fatal(plain)
	}
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	if !redact.LooksLikeSecret(probe) {
		t.Fatal("probe must look like a secret")
	}
	msg := SafeErrorMessage(safety.NewParseError(safety.CodeMalformed, "compose.yaml", probe))
	if strings.Contains(msg, probe) {
		t.Fatal(msg)
	}
}

func TestParseWithLimitsFillsZeros(t *testing.T) {
	d, err := ParseWithLimits(discover.File{Path: "c.yaml", Bytes: []byte("services:\n  web:\n    image: alpine\n"), Origin: "t"}, Limits{})
	if err != nil || d == nil {
		t.Fatalf("%v %+v", err, d)
	}
}
