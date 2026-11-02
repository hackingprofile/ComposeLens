// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

const (
	overlayCustom    = "clx_aaaaaaaaaaaaaaaaaaaaaaaa"
	overlayPublic    = "Pub1!icExampleTokenValueNotASecret99"
	highEntropyNeigh = "aB3$xY9#mK2pQ7nx5wR8tV1cZ4jH6uD0"
)

func overlayProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	env := "" +
		"X_INTERNAL_ID=site-id-0001\n" +
		"CUSTOM_SHAPE=" + overlayCustom + "\n" +
		"SAMPLE_PUB=" + overlayPublic + "\n" +
		// Single-quoted: the value contains "$", which Compose would
		// otherwise expand inside a .env value.
		"NEIGHBOR='" + highEntropyNeigh + "'\n" +
		"PUBLIC_TOKEN=license-spdx-mit\n" +
		"API_TOKEN=keyed-secret-value\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	compose := "" +
		"services:\n" +
		"  web:\n" +
		"    image: alpine\n" +
		"    environment:\n" +
		"      X_INTERNAL_ID: site-id-0001\n" +
		"      CUSTOM_SHAPE: " + overlayCustom + "\n" +
		"      PUBLIC_TOKEN: license-spdx-mit\n" +
		"      API_TOKEN: keyed-secret-value\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func overlayWrite(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func overlayRT(dir string) (Runtime, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info {
		return engine.Info{State: evidence.Absent}
	}}
	return rt, &out, &errb
}

func TestRedactConfigAddsDetectionAndAllowlist(t *testing.T) {
	dir := overlayProject(t)
	add := overlayWrite(t, dir, "add.yaml", `schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"
`)
	both := overlayWrite(t, dir, "both.yaml", `schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"
allowKeys:
  - PUBLIC_TOKEN
allowValues:
  - `+overlayPublic+`
`)

	envText := func(rep inspectReport, key string) (redacted bool, text string) {
		for _, e := range rep.Environment {
			if e.Key != key {
				continue
			}
			if len(e.Sources) == 0 {
				return e.Secret, ""
			}
			s := e.Sources[0]
			if s.Value.Text != nil {
				return s.Value.Redacted, *s.Value.Text
			}
			return s.Value.Redacted, ""
		}
		t.Fatalf("missing key %s", key)
		return false, ""
	}

	rt, out, errb := overlayRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("default: %s", errb.String())
	}
	var def inspectReport
	if err := json.Unmarshal(out.Bytes(), &def); err != nil {
		t.Fatal(err)
	}
	if red, text := envText(def, "X_INTERNAL_ID"); red || text != "site-id-0001" {
		t.Fatalf("default X_INTERNAL_ID redacted=%v text=%q", red, text)
	}
	if red, text := envText(def, "CUSTOM_SHAPE"); red || text != overlayCustom {
		t.Fatalf("default CUSTOM_SHAPE redacted=%v", red)
	}

	out.Reset()
	errb.Reset()
	rt, out, errb = overlayRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--redact", add, "--project-directory", dir}); code != 0 {
		t.Fatalf("add: %s", errb.String())
	}
	var added inspectReport
	if err := json.Unmarshal(out.Bytes(), &added); err != nil {
		t.Fatal(err)
	}
	if red, text := envText(added, "X_INTERNAL_ID"); !red || text != "" {
		t.Fatalf("added key still visible: redacted=%v text=%q", red, text)
	}
	if red, text := envText(added, "CUSTOM_SHAPE"); !red || text != "" {
		t.Fatalf("added value still visible: redacted=%v text=%q", red, text)
	}
	if strings.Contains(out.String(), overlayCustom) || strings.Contains(errb.String(), overlayCustom) {
		t.Fatal("custom-pattern secret leaked after add")
	}

	out.Reset()
	errb.Reset()
	rt, out, errb = overlayRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--redact", both, "--project-directory", dir}); code != 0 {
		t.Fatalf("allow: %s", errb.String())
	}
	var al inspectReport
	if err := json.Unmarshal(out.Bytes(), &al); err != nil {
		t.Fatal(err)
	}
	if red, text := envText(al, "PUBLIC_TOKEN"); red || text != "license-spdx-mit" {
		t.Fatalf("allowlisted key not shown: redacted=%v text=%q", red, text)
	}
	if red, text := envText(al, "SAMPLE_PUB"); red || text != overlayPublic {
		t.Fatalf("allowlisted value not shown: redacted=%v text=%q", red, text)
	}
	if red, text := envText(al, "NEIGHBOR"); !red || text != "" {
		t.Fatalf("neighbor leaked: redacted=%v text=%q", red, text)
	}
	if red, text := envText(al, "API_TOKEN"); !red || text != "" {
		t.Fatalf("API_TOKEN leaked: redacted=%v text=%q", red, text)
	}
	if strings.Contains(out.String(), highEntropyNeigh) || strings.Contains(out.String(), "keyed-secret-value") {
		t.Fatal("real secret leaked while allowlisting")
	}
}

func TestRedactConfigSurfacesConsistent(t *testing.T) {
	dir := overlayProject(t)
	cfg := overlayWrite(t, dir, "add.yaml", `schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"
`)
	commands := [][]string{
		{"inspect", "--json", "--redact", cfg, "--project-directory", dir},
		{"check", "--json", "--redact", cfg, "--project-directory", dir},
		{"check", "--sarif", "--redact", cfg, "--project-directory", dir},
		{"check", "--github", "--redact", cfg, "--project-directory", dir},
		{"explain", "--json", "--redact", cfg, "--project-directory", dir, "web:CUSTOM_SHAPE"},
		{"diff", "--json", "--redact", cfg, "--project-directory", dir, "--left-profile", "a", "--right-profile", "b"},
		{"differential", "--json", "--redact", cfg, "--project-directory", dir},
	}
	for _, args := range commands {
		rt, out, errb := overlayRT(dir)
		code := rt.Run(args)
		if code != 0 && code != exitcode.Assertion {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, overlayCustom) || strings.Contains(blob, "site-id-0001") {
			t.Fatalf("surface leaked custom secret: %v", args[0])
		}
	}
}

func TestRedactDisplayPlaceholderAndCrossRunFingerprints(t *testing.T) {
	dir := overlayProject(t)
	disp := overlayWrite(t, dir, "disp.yaml", "schema: composelens.redact.v0\ndisplay: redacted\n")
	rt, out, errb := overlayRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--redact", disp, "--project-directory", dir}); code != 0 {
		t.Fatalf("err=%s", errb.String())
	}
	var dispRep inspectReport
	if err := json.Unmarshal(out.Bytes(), &dispRep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, e := range dispRep.Environment {
		if e.Key != "API_TOKEN" || len(e.Sources) == 0 {
			continue
		}
		found = true
		if e.Sources[0].Fingerprint != redact.TokenRedacted {
			t.Fatalf("secret display token=%s", e.Sources[0].Fingerprint)
		}
	}
	if !found {
		t.Fatal("API_TOKEN missing")
	}
	if strings.Contains(out.String(), "keyed-secret-value") {
		t.Fatal("raw secret in display-redacted output")
	}

	fp := func() string {
		rt, out, errb := overlayRT(dir)
		if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
			t.Fatal(errb.String())
		}
		var rep inspectReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		for _, e := range rep.Environment {
			if e.Key == "API_TOKEN" && len(e.Sources) > 0 {
				return e.Sources[0].Fingerprint
			}
		}
		t.Fatal("API_TOKEN missing")
		return ""
	}
	a, b := fp(), fp()
	if a == "" || a == b || a == "keyed-secret-value" || !strings.HasPrefix(a, "hmac-sha256:") {
		t.Fatalf("cross-run tokens %s %s", a, b)
	}
}

func TestRedactInvalidAndSecretSafeConfig(t *testing.T) {
	dir := overlayProject(t)
	unknown := overlayWrite(t, dir, "bad.yaml", "schema: composelens.redact.v0\ndisable: true\n")
	rt, out, errb := overlayRT(dir)
	code := rt.Run([]string{"inspect", "--json", "--redact", unknown, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "unknown-field") {
		t.Fatalf("err=%s", errb.String())
	}

	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	secretCfg := overlayWrite(t, dir, "secret.yaml", "schema: composelens.redact.v0\nsecretValues:\n  - "+probe+"\n")
	out.Reset()
	errb.Reset()
	rt, out, errb = overlayRT(dir)
	code = rt.Run([]string{"inspect", "--json", "--redact", secretCfg, "--project-directory", dir})
	if code != exitcode.Input && code != exitcode.Safety {
		t.Fatalf("secret-shaped config code=%d err=%s", code, errb.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(blob, probe) {
		t.Fatal("secret-shaped config diagnostic leaked probe")
	}

	over := filepath.Join(dir, "over.yaml")
	if err := os.WriteFile(over, append([]byte("schema: composelens.redact.v0\n"), bytes.Repeat([]byte("#"), safety.MaxFileBytes)...), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	rt, out, errb = overlayRT(dir)
	code = rt.Run([]string{"inspect", "--json", "--redact", over, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("oversize code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
}

func TestRedactDiscoveredProjectFile(t *testing.T) {
	dir := overlayProject(t)
	overlayWrite(t, dir, redact.DiscoveredName, `schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
`)
	rt, out, errb := overlayRT(dir)
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if strings.Contains(out.String(), "site-id-0001") {
		t.Fatal("discovered config did not redact added key")
	}
}

func TestRedactFlagUsageContract(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"version", "--redact", "x.yaml"}, &out, &errb, nil)
	if code != exitcode.Usage || !strings.Contains(errb.String(), "--redact is not valid with version") {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	out.Reset()
	errb.Reset()
	code = Run([]string{"inspect", "--redact"}, &out, &errb, nil)
	if code != exitcode.Usage || !strings.Contains(errb.String(), "missing value for --redact") {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
}

func TestDoctorListsRedactionConfigImplemented(t *testing.T) {
	dir := overlayProject(t)
	rt, out, errb := overlayRT(dir)
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	has := false
	for _, f := range rep.Features.Implemented {
		if f == "redaction-config" {
			has = true
		}
	}
	if !has {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
}
