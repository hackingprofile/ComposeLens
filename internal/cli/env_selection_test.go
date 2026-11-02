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
	"composelens/internal/safety"
)

func oversizedDotenvProject(t *testing.T) (dir, extra, left, right string) {
	t.Helper()
	dir = t.TempDir()
	compose := "services:\n  web:\n    image: alpine:${TAG}\n    hostname: ${HOSTV}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	big := append([]byte("TAG=from-dotenv\nHOSTV=dotenv-host\n"), bytes.Repeat([]byte("n"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, ".env"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	extra = filepath.Join(dir, "extra.env")
	left = filepath.Join(dir, "left.env")
	right = filepath.Join(dir, "right.env")
	if err := os.WriteFile(extra, []byte("TAG=selected\nHOSTV=selected-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(left, []byte("TAG=left\nHOSTV=left-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, []byte("TAG=right\nHOSTV=right-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, extra, left, right
}

func selectionRT(dir string) (Runtime, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	return Runtime{
		Stdout: &out,
		Stderr: &errb,
		Cwd:    dir,
		Detect: func() engine.Info { return engine.Info{State: evidence.Absent} },
	}, &out, &errb
}

func TestUnselectedOversizedDotenvDoesNotBlockExplicitEnv(t *testing.T) {
	dir, extra, left, right := oversizedDotenvProject(t)
	rt, out, errb := selectionRT(dir)

	code := rt.Run([]string{"diff", "--json", "--left-env-file", left, "--right-env-file", right, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("diff code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "left") || !strings.Contains(out.String(), "right") {
		t.Fatalf("diff missing selected values: %s", out.String())
	}
	if strings.Contains(out.String(), "from-dotenv") || strings.Contains(out.String(), "dotenv-host") {
		t.Fatal("diff applied unselected .env")
	}

	consumers := [][]string{
		{"inspect", "--json", "--env-file", extra, "--project-directory", dir},
		{"check", "--json", "--env-file", extra, "--project-directory", dir},
		{"explain", "--all", "--json", "--env-file", extra, "--project-directory", dir},
		{"report", "--json", "--env-file", extra, "--project-directory", dir},
		{"differential", "--json", "--env-file", extra, "--project-directory", dir},
	}
	for _, args := range consumers {
		out.Reset()
		errb.Reset()
		code := rt.Run(args)
		if code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		if strings.Contains(out.String(), "from-dotenv") {
			t.Fatalf("%v leaked unselected dotenv", args)
		}
	}
}

func TestSelectedOversizedDotenvStillFails(t *testing.T) {
	dir, _, _, _ := oversizedDotenvProject(t)
	rt, out, errb := selectionRT(dir)
	code := rt.Run([]string{"inspect", "--json", "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), string(safety.CodeFileTooLarge)) && !strings.Contains(errb.String(), string(safety.CodeTotalTooLarge)) {
		t.Fatalf("stderr=%s", errb.String())
	}
}

func TestMissingSelectedEnvFileFails(t *testing.T) {
	dir, _, _, _ := oversizedDotenvProject(t)
	rt, out, errb := selectionRT(dir)
	code := rt.Run([]string{"inspect", "--json", "--env-file", filepath.Join(dir, "missing.env"), "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
}

func TestOversizedSelectedEnvFileFails(t *testing.T) {
	dir, extra, _, _ := oversizedDotenvProject(t)
	big := append([]byte("TAG=x\n"), bytes.Repeat([]byte("y"), safety.MaxFileBytes)...)
	if err := os.WriteFile(extra, big, 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := selectionRT(dir)
	code := rt.Run([]string{"check", "--json", "--env-file", extra, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
}

func TestMultipleExplicitEnvFilesKeepOrder(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine:${COLOR}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a.env")
	b := filepath.Join(dir, "b.env")
	if err := os.WriteFile(a, []byte("COLOR=from-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("COLOR=from-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := selectionRT(dir)
	code := rt.Run([]string{"inspect", "--json", "--env-file", a, "--env-file", b, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var img *InterpValueReport
	for i := range rep.Interpolation {
		if rep.Interpolation[i].Path == "services.web.image" {
			img = &rep.Interpolation[i]
			break
		}
	}
	if img == nil || img.Value.Text == nil || *img.Value.Text != "alpine:from-b" {
		t.Fatalf("later env-file must win: %+v", img)
	}
}

func TestComposeEnvFilesCommaList(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine:${COLOR}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a.env")
	b := filepath.Join(dir, "b.env")
	if err := os.WriteFile(a, []byte("COLOR=from-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("COLOR=from-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := selectionRT(dir)
	rt.Environ = []string{"COMPOSE_ENV_FILES=" + a + "," + b}
	code := rt.Run([]string{"inspect", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var img *InterpValueReport
	for i := range rep.Interpolation {
		if rep.Interpolation[i].Path == "services.web.image" {
			img = &rep.Interpolation[i]
			break
		}
	}
	if img == nil || img.Value.Text == nil || *img.Value.Text != "alpine:from-b" {
		t.Fatalf("comma COMPOSE_ENV_FILES later file must win: %+v", img)
	}
}

func TestExplicitEnvFileOverridesMissingPredefined(t *testing.T) {
	dir, extra, _, _ := oversizedDotenvProject(t)
	missing := filepath.Join(dir, "missing.env")
	rt, out, errb := selectionRT(dir)
	rt.Environ = []string{"COMPOSE_ENV_FILES=" + missing}
	code := rt.Run([]string{"inspect", "--json", "--env-file", extra, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String(), "from-dotenv") {
		t.Fatal("unselected .env leaked")
	}
	if !strings.Contains(out.String(), "selected") {
		t.Fatalf("missing selected value: %s", out.String())
	}
}

func TestDiffSideSpecificEnvFilesIgnorePredefined(t *testing.T) {
	dir, extra, left, right := oversizedDotenvProject(t)
	missing := filepath.Join(dir, "missing.env")
	rt, out, errb := selectionRT(dir)
	rt.Environ = []string{"COMPOSE_ENV_FILES=" + extra + "," + missing}
	code := rt.Run([]string{"diff", "--json", "--left-env-file", left, "--right-env-file", right, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("diff code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "left") || !strings.Contains(out.String(), "right") {
		t.Fatalf("diff missing selected values: %s", out.String())
	}
	if strings.Contains(out.String(), "from-dotenv") || strings.Contains(out.String(), "selected-host") {
		t.Fatalf("diff applied predefined extra: %s", out.String())
	}
}
