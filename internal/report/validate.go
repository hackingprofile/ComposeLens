// SPDX-License-Identifier: Apache-2.0

package report

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

var requiredTop = []string{
	"schema", "product", "version", "disclaimer", "determinism", "generatedBy",
	"source", "graph", "check", "diff", "differential", "diagnostics",
	"evidence", "certainty",
}

// optionalTop are optional top-level fields (allowShortSecret records the short-secret opt-in).
var optionalTop = []string{"allowShortSecret"}

var requiredSource = []string{"projectDirectory", "files", "fileEvidence", "services"}

var requiredDiagnostic = []string{"code", "message", "remediation", "doc"}

var requiredService = []string{"name", "identity", "location"}

// ValidateBytes checks a generated package against composelens.report.v0.
// Unknown top-level fields and missing required fields fail.
func ValidateBytes(raw []byte) error {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return fmt.Errorf("report: not JSON: %w", err)
	}
	if err := requireKeys("package", top, requiredTop); err != nil {
		return err
	}
	if err := rejectUnknown("package", top, append(append([]string{}, requiredTop...), optionalTop...)); err != nil {
		return err
	}
	schema, err := asString(top["schema"])
	if err != nil {
		return fmt.Errorf("report: schema: %w", err)
	}
	if schema != Schema {
		return fmt.Errorf("report: schema: want %s, got %s", Schema, schema)
	}
	det, err := asString(top["determinism"])
	if err != nil {
		return fmt.Errorf("report: determinism: %w", err)
	}
	if det != Determinism {
		return fmt.Errorf("report: determinism: want %s, got %s", Determinism, det)
	}
	if err := validateSource(top["source"]); err != nil {
		return err
	}
	if err := requireNestedSchema("graph", top["graph"], "composelens.graph.v0"); err != nil {
		return err
	}
	if err := requireNestedSchema("check", top["check"], "composelens.check.v0"); err != nil {
		return err
	}
	if err := requireCheckAssertion(top["check"]); err != nil {
		return err
	}
	if err := requireNestedSchema("diff", top["diff"], "composelens.diff.v0"); err != nil {
		return err
	}
	if err := requireNestedSchema("differential", top["differential"], "composelens.differential.v0"); err != nil {
		return err
	}
	return validateDiagnostics(top["diagnostics"])
}

func validateSource(raw json.RawMessage) error {
	var src map[string]json.RawMessage
	if err := json.Unmarshal(raw, &src); err != nil {
		return fmt.Errorf("report: source: not an object")
	}
	if err := requireKeys("source", src, requiredSource); err != nil {
		return err
	}
	var files []json.RawMessage
	if err := json.Unmarshal(src["files"], &files); err != nil {
		return fmt.Errorf("report: source.files: not an array")
	}
	var services []json.RawMessage
	if err := json.Unmarshal(src["services"], &services); err != nil {
		return fmt.Errorf("report: source.services: not an array")
	}
	for i, s := range services {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(s, &obj); err != nil {
			return fmt.Errorf("report: source.services[%d]: not an object", i)
		}
		if err := requireKeys(fmt.Sprintf("source.services[%d]", i), obj, requiredService); err != nil {
			return err
		}
		id, err := asString(obj["identity"])
		if err != nil {
			return fmt.Errorf("report: source.services[%d].identity: %w", i, err)
		}
		if !strings.HasPrefix(id, "services.") {
			return fmt.Errorf("report: source.services[%d].identity: want services.<name>, got %s", i, id)
		}
	}
	return nil
}

func requireCheckAssertion(raw json.RawMessage) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("report: check: not an object")
	}
	if _, ok := obj["assertionExit"]; !ok {
		return fmt.Errorf("report: check: missing assertionExit")
	}
	if _, ok := obj["findings"]; !ok {
		return fmt.Errorf("report: check: missing findings")
	}
	if _, ok := obj["gate"]; !ok {
		return fmt.Errorf("report: check: missing gate")
	}
	return nil
}

func validateDiagnostics(raw json.RawMessage) error {
	var items []json.RawMessage
	if err := json.Unmarshal(raw, &items); err != nil {
		return fmt.Errorf("report: diagnostics: not an array")
	}
	for i, item := range items {
		var obj map[string]json.RawMessage
		if err := json.Unmarshal(item, &obj); err != nil {
			return fmt.Errorf("report: diagnostics[%d]: not an object", i)
		}
		if err := requireKeys(fmt.Sprintf("diagnostics[%d]", i), obj, requiredDiagnostic); err != nil {
			return err
		}
		if err := rejectUnknown(fmt.Sprintf("diagnostics[%d]", i), obj, requiredDiagnostic); err != nil {
			return err
		}
	}
	return nil
}

func requireNestedSchema(name string, raw json.RawMessage, want string) error {
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return fmt.Errorf("report: %s: not an object", name)
	}
	got, err := asString(obj["schema"])
	if err != nil {
		return fmt.Errorf("report: %s.schema: %w", name, err)
	}
	if got != want {
		return fmt.Errorf("report: %s.schema: want %s, got %s", name, want, got)
	}
	return nil
}

func requireKeys(where string, obj map[string]json.RawMessage, keys []string) error {
	var missing []string
	for _, k := range keys {
		raw, ok := obj[k]
		if !ok || len(raw) == 0 || string(raw) == "null" {
			missing = append(missing, k)
			continue
		}
		if k == "schema" || k == "product" || k == "version" || k == "disclaimer" || k == "determinism" || k == "generatedBy" || k == "evidence" || k == "certainty" || k == "code" || k == "message" || k == "remediation" || k == "doc" || k == "name" || k == "identity" || k == "projectDirectory" || k == "fileEvidence" {
			s, err := asString(raw)
			if err != nil || strings.TrimSpace(s) == "" {
				missing = append(missing, k)
			}
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("report: %s: missing required field %s", where, strings.Join(missing, ", "))
	}
	return nil
}

func rejectUnknown(where string, obj map[string]json.RawMessage, allowed []string) error {
	ok := map[string]struct{}{}
	for _, k := range allowed {
		ok[k] = struct{}{}
	}
	var extra []string
	for k := range obj {
		if _, known := ok[k]; !known {
			extra = append(extra, k)
		}
	}
	if len(extra) == 0 {
		return nil
	}
	sort.Strings(extra)
	return fmt.Errorf("report: %s: unknown field %s", where, strings.Join(extra, ", "))
}

func asString(raw json.RawMessage) (string, error) {
	var s string
	if err := json.Unmarshal(raw, &s); err != nil {
		return "", fmt.Errorf("not a string")
	}
	return s, nil
}
