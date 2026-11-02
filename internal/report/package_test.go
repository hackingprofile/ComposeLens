// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/check"
	"composelens/internal/differential"
	"composelens/internal/evidence"
	"composelens/internal/provgraph"
)

func samplePackage() Package {
	return Assemble(Input{
		Project: "proj",
		Files: []File{{
			Path: "compose.yaml", Digest: "sha256:00", Origin: "default",
			Evidence: evidence.Known, Certainty: evidence.Proven,
		}},
		Services: []Service{{
			Name: "web", Identity: "services.web",
			Evidence: evidence.Known, Certainty: evidence.Proven,
		}},
		Graph: provgraph.Graph{Evidence: evidence.Known, Certainty: evidence.Proven},
		Check: check.Result{Evidence: evidence.Known, Certainty: evidence.Proven, Gate: check.SevError},
		Differential: differential.Report{
			Schema: differential.Schema, EngineState: "engine-absent",
			Rows: []differential.Row{}, Evidence: evidence.Absent, Certainty: evidence.Proven,
		},
	})
}

func interactivePackage() Package {
	pkg := samplePackage()
	pkg.Graph.Nodes = []provgraph.NodeReport{{
		Target: "services.web",
		Kind:   "service",
		State:  "resolved",
		ShadowChain: []provgraph.LinkReport{
			{Order: 1, Role: "winner", Stage: "compose-file", Source: "compose.yaml", State: "present"},
			{Order: 2, Role: "shadowed", Stage: "override", Source: "compose.override.yaml", State: "overridden"},
		},
		Certainty: evidence.Proven,
		Evidence:  evidence.Known,
	}}
	pkg.Check.Findings = []check.FindingReport{{
		ID:       "CHK01",
		Severity: "warning",
		Target:   "services.web",
		Message:  "example finding",
		Evidence: evidence.Known,
	}}
	pkg.Differential.Rows = []differential.Row{{
		Path:      "services.web.image",
		Kind:      differential.KindField,
		State:     differential.StateMatch,
		Certainty: evidence.Proven,
		Evidence:  evidence.Known,
	}}
	pkg.Diagnostics = []Diagnostic{{
		Code:        "exit.assertion",
		Message:     "check assertion would fire",
		Remediation: "fix the finding or waive it",
		Doc:         "docs/check.md",
	}}
	return pkg
}

func TestValidPackagePasses(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateBytes(raw); err != nil {
		t.Fatal(err)
	}
}

func TestMissingRequiredFieldFails(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	delete(obj, "schema")
	broken, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateBytes(broken)
	if err == nil || !strings.Contains(err.Error(), "missing required field schema") {
		t.Fatalf("want missing schema, got %v", err)
	}
}

func TestUnknownTopLevelFieldFails(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["html"] = "<script>alert(1)</script>"
	broken, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateBytes(broken)
	if err == nil || !strings.Contains(err.Error(), "unknown field html") {
		t.Fatalf("want unknown field, got %v", err)
	}
}

func TestWrongSchemaIdFails(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	obj["schema"] = "composelens.report.v1"
	broken, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	err = ValidateBytes(broken)
	if err == nil || !strings.Contains(err.Error(), "want composelens.report.v0") {
		t.Fatalf("want schema mismatch, got %v", err)
	}
}

func TestEncodeDeterministic(t *testing.T) {
	a, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	b, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("Assemble/Encode not byte-identical")
	}
}

func TestSchemaFilePresent(t *testing.T) {
	p := filepath.Join("..", "..", "schemas", "composelens.report.v0.json")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	if obj["$id"] != Schema {
		t.Fatalf("$id=%v", obj["$id"])
	}
	if _, ok := obj["additionalProperties"]; !ok {
		t.Fatal("schema must reject additional properties")
	}
}
