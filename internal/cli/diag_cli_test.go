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
)

func TestErrorV0IncludesCodeRemediationDoc(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(pol, []byte("schema: composelens.policy.v0\ndisable: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--json", "--policy", pol, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep errorReport
	if err := json.Unmarshal(errb.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != "composelens.error.v0" || rep.Code != "policy.unknown-field" || rep.Remediation == "" || !strings.HasPrefix(rep.Doc, "docs/") {
		t.Fatalf("%+v", rep)
	}
	if strings.Contains(rep.Remediation, "ghp_") {
		t.Fatal("remediation not secret-safe")
	}

	red := filepath.Join(dir, "redact-bad.yaml")
	if err := os.WriteFile(red, []byte("schema: composelens.redact.v0\ndisable: true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	rt = Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code = rt.Run([]string{"inspect", "--redact", red, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("redact code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "code: redact.unknown-field") || !strings.Contains(errb.String(), "See docs/redact.md") {
		t.Fatalf("human redact diagnostic: %s", errb.String())
	}

	errb.Reset()
	out.Reset()
	code = Run([]string{"inspect", "--redact"}, &out, &errb, nil)
	if code != exitcode.Usage || !strings.Contains(errb.String(), "code: cli.usage") {
		t.Fatalf("usage code=%d err=%s", code, errb.String())
	}
}

func TestDoctorNoDeferredCheckStage(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info {
		return engine.Info{State: evidence.Known, Kind: "compose-plugin", Version: "v5.4.0"}
	}}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(blob, "deferred L") {
		t.Fatal("doctor JSON still emits a deferred-stage label")
	}
	if !strings.Contains(blob, "not runtime-verified") {
		t.Fatalf("runtime-verified wording missing: %s", blob)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"doctor", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if strings.Contains(out.String()+errb.String(), "deferred L") {
		t.Fatal("doctor human still emits a deferred-stage label")
	}
}

func TestAssertionJSONCarriesCatalog(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "required-unset")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--json", "--project-directory", dir})
	if code != exitcode.Assertion {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"code": "exit.assertion"`) || !strings.Contains(out.String(), `"doc": "docs/check.md"`) {
		t.Fatalf("assertion catalog missing: %s", out.String())
	}
}
