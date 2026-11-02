// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
)

type failWriter struct{ err error }

func (f failWriter) Write([]byte) (int, error) { return 0, f.err }

func TestInternalErrorPrintsCrashGuidance(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var errb bytes.Buffer
	rt := Runtime{
		Stdout: failWriter{errors.New("disk full")},
		Stderr: &errb,
		Cwd:    dir,
		Detect: func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	code := rt.Run([]string{"doctor", "--json", "--project-directory", dir})
	if code != exitcode.Internal {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	msg := errb.String()
	if !strings.Contains(msg, "did not send this failure anywhere") {
		t.Fatalf("missing telemetry-free line: %s", msg)
	}
	if !strings.Contains(msg, "doctor --bundle") {
		t.Fatalf("missing bundle pointer: %s", msg)
	}
	if strings.Contains(msg, "demo-inline") {
		t.Fatal("source value in crash guidance")
	}
}

func TestRecoveredPanicOmitsValueAndIsTelemetryFree(t *testing.T) {
	const probe = "ghp_ComposeLensPanicProbe99"
	var errb bytes.Buffer
	code := RecoveredPanic(&errb, probe)
	if code != exitcode.Internal {
		t.Fatalf("code=%d", code)
	}
	msg := errb.String()
	if strings.Contains(msg, probe) {
		t.Fatal("panic value leaked")
	}
	if !strings.Contains(msg, "panic was recovered") || !strings.Contains(msg, "did not send") {
		t.Fatalf("%s", msg)
	}
}

func TestDoctorBundleExcludesSecretAndSourceValues(t *testing.T) {
	const (
		probe  = "demo-inline"
		marker = "UNIQUE_SOURCE_MARKER"
	)
	dir := t.TempDir()
	body := "# " + marker + "\nservices:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(dir, "composelens-support.json")
	var stdout, errb bytes.Buffer
	rt := Runtime{
		Stdout: &stdout,
		Stderr: &errb,
		Cwd:    dir,
		Detect: func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	code := rt.Run([]string{"doctor", "--bundle", outPath, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if stdout.Len() != 0 {
		t.Fatalf("stdout=%s", stdout.String())
	}
	raw, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(raw)
	for _, bad := range []string{probe, marker, "API_TOKEN", "services:", "compose.yaml"} {
		if strings.Contains(blob, bad) {
			t.Fatalf("bundle contains %q:\n%s", bad, blob)
		}
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	if _, ok := root["inputs"]; ok {
		t.Fatal("bundle must not include doctor inputs")
	}
	if root["schema"] != supportBundleSchema {
		t.Fatalf("schema=%v", root["schema"])
	}
	if root["telemetry"] != supportTelemetry {
		t.Fatalf("telemetry=%v", root["telemetry"])
	}
	raw2, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}
	// The bundle never overwrites a file, so the second run writes a new one.
	outPath2 := filepath.Join(dir, "composelens-support-2.json")
	code = rt.Run([]string{"doctor", "--bundle", outPath2, "--project-directory", dir})
	if code != 0 {
		t.Fatal(errb.String())
	}
	raw3, err := os.ReadFile(outPath2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw2, raw3) {
		t.Fatal("bundle not deterministic")
	}
}

func TestDoctorJSONUnchangedWhenBundleNotUsed(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"doctor", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.doctor.v0"`) || !strings.Contains(out.String(), `"inputs"`) {
		t.Fatalf("doctor json=%s", out.String())
	}
}

func TestParseArgsDoctorBundle(t *testing.T) {
	opt, err := ParseArgs([]string{"doctor", "--bundle", "out.json"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "doctor" || opt.Bundle != "out.json" || opt.JSON {
		t.Fatalf("%+v", opt)
	}
}
