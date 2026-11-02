// SPDX-License-Identifier: Apache-2.0

package enginecap

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/engineadapter"
	"composelens/internal/evidence"
)

func TestAssessV2Recognized(t *testing.T) {
	r := Assess("v2.29.7", engineadapter.StateCaptured)
	if r.Support != SupportRecognized {
		t.Fatalf("support %s", r.Support)
	}
	if r.Schema != Schema || r.Window != Window {
		t.Fatalf("%s %s", r.Schema, r.Window)
	}
	found := false
	for _, c := range r.Capabilities {
		if c.ID == CapComposeConfig {
			found = true
			if c.State != evidence.Known {
				t.Fatalf("config state %s", c.State)
			}
		}
		if c.ID == CapInterpolation && c.State != evidence.Unknown {
			t.Fatal("must not assume interpolation")
		}
	}
	if !found {
		t.Fatal("missing compose-config")
	}
}

func TestAssessV1Unsupported(t *testing.T) {
	r := Assess("1.29.2", "")
	if r.Support != SupportUnsupported {
		t.Fatalf("support %s want unsupported", r.Support)
	}
	if r.Detail == "" {
		t.Fatal("need clear failure detail")
	}
	if dir := os.Getenv("COMPOSELENS_ENGINECAP_EVIDENCE_DIR"); dir != "" {
		raw, err := json.MarshalIndent(r, "", "  ")
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "unsupported-v1.json"), append(raw, '\n'), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAssessV3RecognizedPluginFamily(t *testing.T) {
	r := Assess("v3.0.0", "")
	if r.Support != SupportRecognized {
		t.Fatalf("support %s", r.Support)
	}
}

func TestAssessV5RecognizedPluginFamily(t *testing.T) {
	r := Assess("v5.5.0", engineadapter.StateCaptured)
	if r.Support != SupportRecognized {
		t.Fatalf("support %s", r.Support)
	}
}

func TestAssessV2NeverEmitsSupportedToken(t *testing.T) {
	r := Assess("v5.4.0", "")
	if r.Support == "supported" {
		t.Fatal("v2+ family must not emit bare supported")
	}
	if r.Support != SupportRecognized {
		t.Fatalf("support %s", r.Support)
	}
}

func TestAssessUnparsedUnknown(t *testing.T) {
	r := Assess("not-a-version", "")
	if r.Support != SupportUnknown {
		t.Fatalf("support %s", r.Support)
	}
}

func TestNoStaleDeferredCheckStage(t *testing.T) {
	r := Assess("v5.4.0", "")
	for _, c := range r.Capabilities {
		if strings.Contains(c.Detail, "deferred L") {
			t.Fatalf("stale deferred-stage wording on %s: %s", c.ID, c.Detail)
		}
	}
	if !strings.Contains(r.Capabilities[1].Detail, "not runtime-verified") {
		t.Fatalf("runtime-verified wording missing: %+v", r.Capabilities[1])
	}
}

func TestAssessAbsent(t *testing.T) {
	r := Assess("", engineadapter.StateEngineAbsent)
	if r.Support != SupportAbsent {
		t.Fatalf("support %s", r.Support)
	}
}

func TestFromDetectAbsent(t *testing.T) {
	r := FromDetect(evidence.Absent, "")
	if r.Support != SupportAbsent {
		t.Fatalf("support %s", r.Support)
	}
}

func TestMajorParse(t *testing.T) {
	cases := map[string]int{
		"v2.29.7":             2,
		"2.24.0":              2,
		"v2.29.7-desktop.1":   2,
		"1.29.2":              1,
		"Docker Compose v2.5": 0,
	}
	for in, want := range cases {
		got, ok := major(in)
		if in == "Docker Compose v2.5" {
			if ok {
				t.Fatalf("%q parsed %d", in, got)
			}
			continue
		}
		if !ok || got != want {
			t.Fatalf("%q got %d ok=%t want %d", in, got, ok, want)
		}
	}
}
