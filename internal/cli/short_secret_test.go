// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
	"composelens/internal/safety"
)

// The short-secret table, with the expected exits.
// Commands whose output carries project values refuse a collected secret
// shorter than 6 bytes; doctor and reproduce carry none and do not refuse.
func TestShortSecretTable(t *testing.T) {
	svc := func(env string) map[string]string {
		return map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n" + env}
	}
	rows := []struct {
		name  string
		files map[string]string
		want  map[string]int // inspect, check, doctor, reproduce, report
	}{
		{"root (4 bytes)", svc("      PASSWORD: \"root\"\n"), map[string]int{"inspect": 4, "check": 4, "doctor": 0, "reproduce": 0, "report": 4}},
		{"12345", svc("      PASSWORD: \"12345\"\n"), map[string]int{"inspect": 4, "check": 4, "doctor": 0, "reproduce": 0, "report": 4}},
		{"123456", svc("      PASSWORD: \"123456\"\n"), map[string]int{"inspect": 0, "check": 0, "doctor": 0, "reproduce": 0, "report": 0}},
		{"three e-acute = 6 bytes", svc("      PASSWORD: \"ééé\"\n"), map[string]int{"inspect": 0, "check": 0, "doctor": 0, "reproduce": 0, "report": 0}},
		{"empty", svc("      PASSWORD: \"\"\n"), map[string]int{"inspect": 0, "check": 0, "doctor": 0, "reproduce": 0, "report": 0}},
		{"externalized to .env", map[string]string{"compose.yaml": "services: {web: {image: alpine:3.21, environment: {PASSWORD: \"${PASSWORD}\"}}}\n", ".env": "PASSWORD=root\n"}, map[string]int{"inspect": 4, "check": 4, "doctor": 0, "reproduce": 0, "report": 4}},
		{"disabled service", map[string]string{"compose.yaml": "services: {web: {image: alpine:3.21, profiles: [debug], environment: {PASSWORD: root}}}\n"}, map[string]int{"inspect": 4, "check": 4, "doctor": 0, "reproduce": 0, "report": 4}},
	}
	args := map[string][]string{
		"inspect": {"inspect", "--json"}, "check": {"check", "--json"}, "doctor": {"doctor", "--json"},
		"reproduce": {"reproduce", "--json"}, "report": {"report", "--json", "--no-engine"},
	}
	for _, r := range rows {
		dir := writeProbeProject(t, r.files)
		for cmd, want := range r.want {
			rt, out, errb := reportRT(dir)
			if code := rt.Run(append(append([]string{}, args[cmd]...), "--project-directory", dir)); code != want {
				t.Errorf("%s / %s: code=%d want %d err=%.160s", r.name, cmd, code, want, errb.String())
			}
			if want == 4 && out.Len() != 0 {
				t.Errorf("%s / %s: refused output still wrote stdout", r.name, cmd)
			}
		}
	}
}

// --allow-short-secret KEY is an exact, per-key opt-in. The
// value stays withheld, a warning is printed, and JSON records the opt-in.
func TestAllowShortSecretIsExactAndWithheld(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n      PASSWORD: \"root\"\n"})
	for _, cmd := range [][]string{{"inspect", "--json"}, {"check", "--json"}, {"report", "--json", "--no-engine"}, {"explain", "web:PASSWORD", "--json"}, {"explain", "--all", "--json"}} {
		rt, out, errb := reportRT(dir)
		code := rt.Run(append(append([]string{}, cmd...), "--allow-short-secret", "PASSWORD", "--project-directory", dir))
		if code != exitcode.OK {
			t.Errorf("%v: code=%d err=%s", cmd, code, errb.String())
			continue
		}
		for _, s := range decodedStrings(out.Bytes()) {
			if s == "root" {
				t.Errorf("%v: short secret printed", cmd)
			}
		}
		if !strings.Contains(errb.String(), "--allow-short-secret") || !strings.Contains(errb.String(), "PASSWORD") {
			t.Errorf("%v: no warning: %q", cmd, errb.String())
		}
		var doc map[string]any
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Fatal(err)
		}
		if got, _ := doc["allowShortSecret"].([]any); len(got) != 1 || got[0] != "PASSWORD" {
			t.Errorf("%v: allowShortSecret not recorded: %v", cmd, doc["allowShortSecret"])
		}
	}
	// Human views withhold too.
	rt, out, _ := reportRT(dir)
	if code := rt.Run([]string{"inspect", "--allow-short-secret", "PASSWORD", "--project-directory", dir}); code != exitcode.OK || strings.Contains(out.String(), "root") {
		t.Errorf("human inspect code=%d", code)
	}
	// Another key does not unlock PASSWORD; wildcards and empty names are usage.
	rt, _, _ = reportRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--allow-short-secret", "OTHER", "--project-directory", dir}); code != exitcode.Safety {
		t.Errorf("other key: code=%d", code)
	}
	for _, bad := range []string{"PASS*", "PASS?", "*", "[A-Z]*"} {
		rt, _, _ = reportRT(dir)
		if code := rt.Run([]string{"inspect", "--json", "--allow-short-secret", bad, "--project-directory", dir}); code != exitcode.Usage {
			t.Errorf("%q: code=%d", bad, code)
		}
	}
	rt, _, _ = reportRT(dir)
	if code := rt.Run([]string{"version", "--allow-short-secret", "PASSWORD"}); code != exitcode.Usage {
		t.Errorf("version with the flag: code=%d", code)
	}
}

// The refusal explains itself in the selected format — stable
// code, key name and file:line, remediation, doc — and never echoes the value.
func TestShortSecretRefusalUsesTheSelectedFormat(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n      PASSWORD: \"root\"\n"})
	rt, out, errb := reportRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != exitcode.Safety || out.Len() != 0 {
		t.Fatalf("code=%d stdout=%d", code, out.Len())
	}
	var doc struct {
		Schema, Code, Message, Remediation, Doc string
	}
	if err := json.Unmarshal(errb.Bytes(), &doc); err != nil {
		t.Fatalf("stderr is not the error document: %v\n%s", err, errb.String())
	}
	if doc.Schema != "composelens.error.v0" || doc.Code != "safety.short-secret" || doc.Remediation == "" || doc.Doc != "docs/privacy.md" {
		t.Errorf("error document: %+v", doc)
	}
	if !strings.Contains(doc.Message, "PASSWORD") || !strings.Contains(doc.Message, "compose.yaml:5") {
		t.Errorf("message does not name key and file:line: %q", doc.Message)
	}
	if !strings.Contains(doc.Remediation, "--allow-short-secret") {
		t.Errorf("remediation does not name the opt-in: %q", doc.Remediation)
	}
	if strings.Contains(errb.String(), "root") {
		t.Errorf("refusal echoes the value: %s", errb.String())
	}
	rt, _, errb = reportRT(dir)
	if code := rt.Run([]string{"inspect", "--project-directory", dir}); code != exitcode.Safety ||
		!strings.Contains(errb.String(), "code: safety.short-secret") || !strings.Contains(errb.String(), "PASSWORD") || strings.Contains(errb.String(), "root") {
		t.Errorf("human refusal: code=%d %s", code, errb.String())
	}
}

// docs/privacy.md states the real short-secret rule.
func TestPrivacyDocStatesTheShortSecretRule(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "docs", "privacy.md"))
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)
	if safety.MinScanLen != 6 {
		t.Fatalf("MinScanLen=%d; update docs/privacy.md", safety.MinScanLen)
	}
	for _, want := range []string{"shorter than **6 bytes**", "bytes, not characters", "Empty values are skipped",
		"`doctor` and `reproduce` carry no project values", "disabled services included", "does **not** help",
		"--allow-short-secret <KEY>", "safety.short-secret", "allowShortSecret"} {
		if !strings.Contains(doc, want) {
			t.Errorf("docs/privacy.md does not state %q", want)
		}
	}
	if strings.Contains(doc, "There is no override") {
		t.Error("docs/privacy.md still says there is no override")
	}
}
