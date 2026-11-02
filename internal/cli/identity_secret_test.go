// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
	"composelens/internal/report"
)

func identityCompose(t *testing.T, service, extra string) string {
	t.Helper()
	dir := t.TempDir()
	body := "services:\n  \"" + service + "\":\n"
	if extra == "" {
		extra = "    image: alpine\n"
	} else if !strings.Contains(extra, "image:") {
		extra = "    image: alpine\n" + extra
	}
	body += extra
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestIdentityCommandsExitZero(t *testing.T) {
	rows := []struct {
		name    string
		service string
		extra   string
		needle  string
	}{
		{name: "javascript-alert", service: "svc-javascript:alert(1)", needle: "svc-javascript:alert(1)"},
		{name: "python-print", service: "svc-python:print(1)", needle: "svc-python:print(1)"},
		{name: "xxx-javascript", service: "xxx-javascript:alert(9)", needle: "xxx-javascript:alert(9)"},
		{name: "scheme-shaped-value", service: "web", extra: "    image: \"foo:bar(1)\"\n", needle: "foo:bar(1)"},
		{name: "dotted-identity", service: "web.api", needle: "web.api"},
		{name: "unicode-identity", service: "svc-αβγδεζηθ", needle: "svc-αβγδεζηθ"},
		{name: "long-nonsecret", service: "abcdefghijklmnopqrstuvwxyz0123", needle: "abcdefghijklmnopqrstuvwxyz0123"},
	}
	cmds := [][]string{
		{"inspect"},
		{"check"},
		{"explain", "--all"},
		{"report", "--json"},
		{"report", "--html"},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			dir := identityCompose(t, row.service, row.extra)
			for _, cmd := range cmds {
				t.Run(strings.Join(cmd, "_"), func(t *testing.T) {
					rt, out, errb := reportRT(dir)
					code := rt.Run(append(append([]string{}, cmd...), "--project-directory", dir))
					if code != 0 {
						t.Fatalf("%v code=%d err=%s", cmd, code, errb.String())
					}
					if strings.Contains(errb.String(), "a secret value would leak") {
						t.Fatalf("%v false-closed on non-secret: %s", cmd, errb.String())
					}
					blob := out.String()
					wantNeedle := cmd[0] == "inspect" || (cmd[0] == "report")
					if wantNeedle && !strings.Contains(blob, row.needle) {
						t.Fatalf("%v missing identity/value %q in output", cmd, row.needle)
					}
					if cmd[0] == "report" && len(cmd) > 1 && cmd[1] == "--html" {
						page := out.Bytes()
						if bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
							t.Fatal("innerHTML")
						}
						if sinks := report.LiveSinks(page); len(sinks) > 0 {
							t.Fatalf("live sinks: %v", sinks)
						}
						if bytes.Contains(page, []byte(`href="javascript:`)) || bytes.Contains(page, []byte(`src="javascript:`)) {
							t.Fatal("javascript: sink")
						}
					}
				})
			}
		})
	}
}

func TestGenuineSecretRedactedOrFailClosed(t *testing.T) {
	const probe = "AKIAIOSFODNN7EXAMPLE"
	dir := identityCompose(t, "svc-javascript:alert(1)", "    environment:\n      API_TOKEN: "+probe+"\n")
	cmds := [][]string{
		{"inspect", "--json"},
		{"check", "--json"},
		{"explain", "--all", "--json"},
		{"report", "--json"},
		{"report", "--html"},
	}
	for _, cmd := range cmds {
		t.Run(strings.Join(cmd, "_"), func(t *testing.T) {
			rt, out, errb := reportRT(dir)
			code := rt.Run(append(append([]string{}, cmd...), "--project-directory", dir))
			blob := out.String() + errb.String()
			if strings.Contains(blob, probe) {
				t.Fatalf("%v leaked genuine secret, code=%d", cmd, code)
			}
			if code != 0 && code != exitcode.Safety {
				t.Fatalf("%v code=%d err=%s", cmd, code, errb.String())
			}
			if code == exitcode.Safety {
				if out.Len() != 0 {
					t.Fatalf("%v fail-closed but wrote stdout", cmd)
				}
				if !strings.Contains(errb.String(), "a secret value would leak") {
					t.Fatalf("%v safety without leak message: %s", cmd, errb.String())
				}
			}
		})
	}
}

func TestWouldLeakStillExit4(t *testing.T) {
	const probe = "AKIAIOSFODNN7EXAMPLE"
	dir := identityCompose(t, "web", "")
	rt, out, errb := reportRT(dir)
	code := rt.emit([]byte(`{"note":"`+probe+`"}`), []string{probe})
	if code != exitcode.Safety {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout leaked: %s", out.String())
	}
	if !strings.Contains(errb.String(), "a secret value would leak") {
		t.Fatalf("stderr=%s", errb.String())
	}
}
