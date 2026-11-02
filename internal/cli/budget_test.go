// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/safety"
)

func paddedYAML(svc string, pad int) []byte {
	body := fmt.Sprintf("services:\n  %s:\n    image: alpine\n", svc)
	return append([]byte(body), bytes.Repeat([]byte("#"), pad)...)
}

func TestInspectTransitiveIncludeExceedsBudget(t *testing.T) {
	dir := t.TempDir()
	pad := 900 * 1024
	names := []string{"compose.yaml", "a.yaml", "b.yaml", "c.yaml", "d.yaml"}
	for i, name := range names {
		var body string
		if i+1 < len(names) {
			body = fmt.Sprintf("include:\n  - %s\nservices:\n  s%d:\n    image: alpine\n", names[i+1], i)
		} else {
			body = fmt.Sprintf("services:\n  s%d:\n    image: alpine\n", i)
		}
		if err := os.WriteFile(filepath.Join(dir, name), append([]byte(body), bytes.Repeat([]byte("#"), pad)...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must stay empty before analysis: %s", out.String())
	}
	if !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("stderr=%s", errb.String())
	}
}

func TestInspectTooManyFiles(t *testing.T) {
	dir := t.TempDir()
	tiny := []byte("services:\n  web:\n    image: alpine\n")
	args := []string{"inspect", "--project-directory", dir}
	for i := 0; i <= safety.MaxTotalFiles; i++ {
		p := filepath.Join(dir, fmt.Sprintf("f%03d.yaml", i))
		if err := os.WriteFile(p, tiny, 0o644); err != nil {
			t.Fatal(err)
		}
		args = append(args, "-f", p)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run(args)
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), string(safety.CodeTooManyFiles)) {
		t.Fatalf("stderr=%s", errb.String())
	}
}

func TestCheckEnvAndPolicyContributeToBudget(t *testing.T) {
	dir := t.TempDir()
	pad := 900 * 1024
	var files []string
	for i := 0; i < 4; i++ {
		p := filepath.Join(dir, fmt.Sprintf("c%d.yaml", i))
		if err := os.WriteFile(p, paddedYAML(fmt.Sprintf("s%d", i), pad), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	envp := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(envp, append([]byte("FOO=bar\n"), bytes.Repeat([]byte("#"), pad)...), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	args := []string{"inspect", "--project-directory", dir, "--env-file", envp}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	code := rt.Run(args)
	if code != exitcode.Input || !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("env aggregate code=%d err=%s", code, errb.String())
	}

	pol := filepath.Join(dir, "policy.yaml")
	if err := os.WriteFile(pol, append([]byte("schema: composelens.policy.v0\n"), bytes.Repeat([]byte("#"), pad)...), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	args = []string{"check", "--project-directory", dir, "--policy", pol}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	rt = Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code = rt.Run(args)
	if code != exitcode.Input || !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("policy aggregate code=%d err=%s", code, errb.String())
	}
	if strings.Contains(errb.String(), "CHK01") || strings.Contains(out.String(), "CHK01") {
		t.Fatal("analysis findings must not run after budget failure")
	}
}

func TestInspectSecretSafeBudgetFailure(t *testing.T) {
	dir := t.TempDir()
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	secretDir := filepath.Join(dir, probe)
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	pad := 900 * 1024
	var files []string
	for i := 0; i < 5; i++ {
		p := filepath.Join(secretDir, fmt.Sprintf("c%d.yaml", i))
		if err := os.WriteFile(p, paddedYAML(fmt.Sprintf("s%d", i), pad), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: secretDir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	args := []string{"inspect", "--project-directory", secretDir}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	code := rt.Run(args)
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if strings.Contains(errb.String(), probe) || strings.Contains(out.String(), probe) {
		t.Fatalf("leaked secret path: out=%s err=%s", out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("stderr=%s", errb.String())
	}
}

func TestNormalProjectUnaffected(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out1, err1, out2, err2 bytes.Buffer
	rt1 := Runtime{Stdout: &out1, Stderr: &err1, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	rt2 := Runtime{Stdout: &out2, Stderr: &err2, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	args := []string{"check", "--json", "--project-directory", dir}
	c1 := rt1.Run(args)
	c2 := rt2.Run(args)
	if c1 != 0 || c2 != 0 {
		t.Fatalf("codes %d %d err=%s %s", c1, c2, err1.String(), err2.String())
	}
	if out1.String() != out2.String() {
		t.Fatal("normal project output must be stable")
	}
	if !strings.Contains(out1.String(), `"findings"`) {
		t.Fatalf("unexpected %s", out1.String())
	}
}

func TestInspectOversizedContainerEnvFile(t *testing.T) {
	dir := t.TempDir()
	huge := append([]byte("COLOR=blue\n"), bytes.Repeat([]byte("#"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, "huge.env"), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    env_file: huge.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must stay empty: %s", out.String())
	}
	if !strings.Contains(errb.String(), string(safety.CodeFileTooLarge)) {
		t.Fatalf("stderr=%s", errb.String())
	}
	if strings.Contains(errb.String(), "COLOR=blue") {
		t.Fatal("leaked env content")
	}
}

func TestInspectContainerEnvFileAggregate(t *testing.T) {
	dir := t.TempDir()
	pad := bytes.Repeat([]byte("#"), 900*1024)
	var body strings.Builder
	body.WriteString("services:\n  web:\n    image: alpine\n    env_file:\n")
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("e%d.env", i)
		if err := os.WriteFile(filepath.Join(dir, name), append([]byte("K=v\n"), pad...), 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&body, "      - %s\n", name)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--project-directory", dir})
	if code != exitcode.Input || out.Len() != 0 || !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
}

func TestInspectNormalEnvFileUnchanged(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "containerenv", "override")
	var out1, err1, out2, err2 bytes.Buffer
	rt1 := Runtime{Stdout: &out1, Stderr: &err1, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	rt2 := Runtime{Stdout: &out2, Stderr: &err2, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	args := []string{"inspect", "--json", "--project-directory", dir}
	c1 := rt1.Run(args)
	c2 := rt2.Run(args)
	if c1 != 0 || c2 != 0 {
		t.Fatalf("codes %d %d err=%s %s", c1, c2, err1.String(), err2.String())
	}
	if out1.String() != out2.String() {
		t.Fatal("normal env_file inspect must be stable")
	}
	if !strings.Contains(out1.String(), `"from-compose"`) || !strings.Contains(out1.String(), `"file"`) {
		t.Fatalf("values drifted: %s", out1.String())
	}
}

func TestInspectRedactConfigContributesToBudget(t *testing.T) {
	dir := t.TempDir()
	pad := 900 * 1024
	var files []string
	for i := 0; i < 4; i++ {
		p := filepath.Join(dir, fmt.Sprintf("c%d.yaml", i))
		if err := os.WriteFile(p, paddedYAML(fmt.Sprintf("s%d", i), pad), 0o644); err != nil {
			t.Fatal(err)
		}
		files = append(files, p)
	}
	red := filepath.Join(dir, "redact.yaml")
	if err := os.WriteFile(red, append([]byte("schema: composelens.redact.v0\n"), bytes.Repeat([]byte("#"), pad)...), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	args := []string{"inspect", "--project-directory", dir, "--redact", red}
	for _, f := range files {
		args = append(args, "-f", f)
	}
	code := rt.Run(args)
	if code != exitcode.Input || !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("redact aggregate code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
}
