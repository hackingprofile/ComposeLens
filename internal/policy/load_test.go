// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"composelens/internal/safety"
)

func TestParseValidYAMLAndJSON(t *testing.T) {
	yamlBody := "schema: composelens.policy.v0\nrules:\n  - id: CHK05\n    enabled: false\n  - id: CHK01\n    severity: error\nexceptions:\n  - rule: CHK03\n    expires: \"2099-12-31\"\n"
	doc, err := Parse([]byte(yamlBody))
	if err != nil {
		t.Fatal(err)
	}
	if doc.Schema != Schema || doc.Enabled("CHK05") || doc.Severity("CHK01", "warning") != "error" || !doc.Waived("CHK03") || !doc.Enabled("CHK02") || doc.GateLevel() != DefaultGate {
		t.Fatalf("%+v", doc)
	}
	gated, err := Parse([]byte("schema: composelens.policy.v0\ngate: warning\n"))
	if err != nil {
		t.Fatal(err)
	}
	if gated.GateLevel() != "warning" {
		t.Fatalf("gate %s", gated.GateLevel())
	}
	js := `{"schema":"composelens.policy.v0","rules":{"CHK05":{"enabled":false}}}`
	doc2, err := Parse([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if doc2.Enabled("CHK05") {
		t.Fatal("json map rule")
	}
}

func TestParseInvalidTable(t *testing.T) {
	nowUTC = func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) }
	t.Cleanup(func() { nowUTC = func() time.Time { return time.Now().UTC() } })
	cases := []struct {
		name string
		body string
		kind string
	}{
		{"empty", "", KindMalformed},
		{"malformed", "{not json", KindMalformed},
		{"missing-schema", "rules: []\n", KindMissingSchema},
		{"unknown-schema", "schema: composelens.policy.v1\n", KindUnknownSchema},
		{"unknown-field", "schema: composelens.policy.v0\nfoo: 1\n", KindUnknownField},
		{"unknown-rule", "schema: composelens.policy.v0\nrules:\n  - id: CHK99\n", KindUnknownRule},
		{"unknown-rule-field", "schema: composelens.policy.v0\nrules:\n  - id: CHK01\n    extra: 1\n", KindUnknownField},
		{"exception-missing-date", "schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n", KindExceptionDate},
		{"exception-invalid-date", "schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n    expires: not-a-date\n", KindExceptionDate},
		{"exception-past", "schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n    expires: \"2020-01-01\"\n", KindExceptionDate},
		{"threshold", "schema: composelens.policy.v0\nrules:\n  - id: CHK01\n    threshold: 1\n", KindUnknownField},
		{"unknown-gate", "schema: composelens.policy.v0\ngate: fatal\n", KindInvalidRule},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Parse([]byte(tc.body))
			if err == nil {
				t.Fatal("expected error")
			}
			pe, ok := err.(*Error)
			if !ok || pe.Kind != tc.kind {
				t.Fatalf("got %#v want kind %s", err, tc.kind)
			}
		})
	}
}

func TestParseDoesNotEchoSecret(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	_, err := Parse([]byte("schema: composelens.policy.v0\n" + probe + ": true\n"))
	if err == nil {
		t.Fatal("expected unknown field")
	}
	if strings.Contains(err.Error(), probe) {
		t.Fatalf("echoed secret: %v", err)
	}
}

func TestLoadMissingFile(t *testing.T) {
	_, _, err := Load(filepath.Join(t.TempDir(), "nope.yaml"))
	if err == nil {
		t.Fatal("expected missing")
	}
	pe := err.(*Error)
	if pe.Kind != KindMissingFile {
		t.Fatalf("%#v", pe)
	}
}

func TestSecretFragmentsSkipsShortFile(t *testing.T) {
	if frags := SecretFragments([]byte("{")); len(frags) != 0 {
		t.Fatalf("short malformed file must not be a guard fragment: %v", frags)
	}
}

func TestSecretFragmentsCapturesProbe(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	frags := SecretFragments([]byte("schema: composelens.policy.v0\n" + probe + ": true\n"))
	found := false
	for _, f := range frags {
		if f == probe {
			found = true
		}
		if f == "schema: composelens.policy.v0\n"+probe+": true\n" {
			t.Fatal("whole policy file treated as one fragment")
		}
	}
	if !found {
		t.Fatalf("missing probe in %v", frags)
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "p.yaml")
	if err := os.WriteFile(p, []byte("schema: composelens.policy.v0\nrules:\n  - id: CHK05\n    enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	doc, raw, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if len(raw) == 0 || doc.Enabled("CHK05") {
		t.Fatal("load")
	}
}

func testdata(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestParseDuplicateFieldsYAMLAndJSON(t *testing.T) {
	cases := []string{
		"dup-schema.yaml", "dup-schema.json",
		"dup-rule-key.yaml", "dup-rule-key.json",
		"dup-enabled.yaml", "dup-enabled.json",
		"dup-expires.yaml", "dup-expires.json",
	}
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(testdata(t, name))
			if err == nil {
				t.Fatal("expected duplicate-field")
			}
			pe, ok := err.(*Error)
			if !ok || pe.Kind != KindDuplicateField {
				t.Fatalf("got %#v", err)
			}
			if strings.Contains(err.Error(), "composelens.policy.bad") {
				t.Fatalf("exposed duplicate value: %v", err)
			}
		})
	}
}

func TestParseThresholdRejected(t *testing.T) {
	for _, name := range []string{"threshold.yaml", "threshold.json"} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(testdata(t, name))
			if err == nil {
				t.Fatal("expected unknown-field")
			}
			pe, ok := err.(*Error)
			if !ok || pe.Kind != KindUnknownField {
				t.Fatalf("got %#v", err)
			}
		})
	}
}

func TestParseDuplicateDoesNotEchoSecretValue(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	body := `{"schema":"` + probe + `","schema":"composelens.policy.v0"}`
	_, err := Parse([]byte(body))
	if err == nil {
		t.Fatal("expected duplicate-field")
	}
	if strings.Contains(err.Error(), probe) {
		t.Fatalf("echoed secret: %v", err)
	}
	pe := err.(*Error)
	if pe.Kind != KindDuplicateField {
		t.Fatalf("%#v", pe)
	}
}

func TestParseDeterministicUnknownFields(t *testing.T) {
	body := testdata(t, "alpha-omega.yaml")
	var first string
	for i := 0; i < 100; i++ {
		_, err := Parse(body)
		if err == nil {
			t.Fatal("expected unknown-field")
		}
		pe, ok := err.(*Error)
		if !ok || pe.Kind != KindUnknownField {
			t.Fatalf("got %#v", err)
		}
		if !strings.Contains(err.Error(), "alpha") {
			t.Fatalf("want alpha first, got %v", err)
		}
		if strings.Contains(err.Error(), "omega") {
			t.Fatalf("must not mention later key: %v", err)
		}
		if i == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("diagnostic drifted: %q vs %q", first, err.Error())
		}
	}
}

func TestParseDeterministicRuleAndExceptionMaps(t *testing.T) {
	_, err := Parse(testdata(t, "multi-rule.yaml"))
	if err == nil || !strings.Contains(err.Error(), "CHK98") {
		t.Fatalf("want CHK98 first: %v", err)
	}
	_, err = Parse(testdata(t, "multi-exception.yaml"))
	if err == nil || !strings.Contains(err.Error(), "beta") {
		t.Fatalf("want beta first: %v", err)
	}
}

func TestParseSingleDocumentAndTrailing(t *testing.T) {
	_, err := Parse(testdata(t, "multi-doc.yaml"))
	if err == nil {
		t.Fatal("expected multiple-documents")
	}
	pe := err.(*Error)
	if pe.Kind != KindMultiDoc {
		t.Fatalf("%#v", pe)
	}
	_, err = Parse([]byte("schema: composelens.policy.v0\n---\n"))
	if err == nil {
		t.Fatal("expected empty second document to fail")
	}
	pe = err.(*Error)
	if pe.Kind != KindMultiDoc && pe.Kind != KindTrailing {
		t.Fatalf("second document kind %#v", pe)
	}
	_, err = Parse([]byte(`{"schema":"composelens.policy.v0"}{"x":1}`))
	if err == nil {
		t.Fatal("expected trailing")
	}
	pe = err.(*Error)
	if pe.Kind != KindTrailing {
		t.Fatalf("%#v", pe)
	}
}

func TestParseRejectsYAMLConstructs(t *testing.T) {
	for _, name := range []string{"alias.yaml", "merge.yaml", "cycle.yaml"} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(testdata(t, name))
			if err == nil {
				t.Fatal("expected unsupported-construct")
			}
			pe, ok := err.(*Error)
			if !ok || pe.Kind != KindUnsupported {
				t.Fatalf("got %#v", err)
			}
		})
	}
}

func TestParseBounds(t *testing.T) {
	_, err := Parse([]byte{0xff, 0xfe, 0xfd})
	if err == nil || err.(*Error).Kind != KindEncoding {
		t.Fatalf("utf8: %v", err)
	}

	var deep strings.Builder
	const nest = 70
	for i := 0; i < nest; i++ {
		deep.WriteString(`{"a":`)
	}
	deep.WriteByte('1')
	for i := 0; i < nest; i++ {
		deep.WriteByte('}')
	}
	_, err = Parse([]byte(deep.String()))
	if err == nil || err.(*Error).Kind != KindTooDeep {
		t.Fatalf("json deep: %v", err)
	}

	var ydeep strings.Builder
	for i := 0; i < nest; i++ {
		ydeep.WriteString(strings.Repeat(" ", i) + "a:\n")
	}
	ydeep.WriteString(strings.Repeat(" ", nest) + "1\n")
	_, err = Parse([]byte(ydeep.String()))
	if err == nil || err.(*Error).Kind != KindTooDeep {
		t.Fatalf("yaml deep: %v", err)
	}

	var many strings.Builder
	many.WriteString(`{"schema":"composelens.policy.v0","x":[`)
	for i := 0; i < safety.MaxYAMLNodes; i++ {
		if i > 0 {
			many.WriteByte(',')
		}
		many.WriteByte('1')
	}
	many.WriteString(`]}`)
	_, err = Parse([]byte(many.String()))
	if err == nil || err.(*Error).Kind != KindTooManyNodes {
		t.Fatalf("too many: %v", err)
	}
}

func TestLoadExactAndOverByteBound(t *testing.T) {
	dir := t.TempDir()
	header := "schema: composelens.policy.v0\n#"
	exact := make([]byte, safety.MaxFileBytes)
	copy(exact, header)
	for i := len(header); i < len(exact); i++ {
		exact[i] = 'x'
	}
	p := filepath.Join(dir, "exact.yaml")
	if err := os.WriteFile(p, exact, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Load(p); err != nil {
		t.Fatalf("exact limit: %v", err)
	}
	over := make([]byte, len(exact)+1)
	copy(over, exact)
	over[len(exact)] = 'y'
	op := filepath.Join(dir, "over.yaml")
	if err := os.WriteFile(op, over, 0o644); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load(op)
	if err == nil || err.(*Error).Kind != KindTooLarge {
		t.Fatalf("over: %v", err)
	}
}

func TestLoadChargesSharedBudget(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "policy.yaml")
	body := "schema: composelens.policy.v0\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	b := safety.NewBudget()
	if err := b.ChargePath("precharged.yaml", safety.MaxTotalBytes-8); err != nil {
		t.Fatal(err)
	}
	_, _, err := Load(p, b)
	if !safety.IsResourceBound(err) || safety.CodeOf(err) != safety.CodeTotalTooLarge {
		t.Fatalf("got %v", err)
	}
}
