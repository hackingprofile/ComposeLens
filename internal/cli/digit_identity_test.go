// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

func digitCompose(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestHumanShowsDigitServiceIdentities(t *testing.T) {
	dir := digitCompose(t, ""+
		"services:\n"+
		"  my-application-service-v2:\n"+
		"    image: alpine\n"+
		"    environment:\n"+
		"      COLOR: ${TINT}\n"+
		"  payment-gateway-worker-01:\n"+
		"    image: ${MISSING:?need}\n")
	if err := os.WriteFile(filepath.Join(dir, "left.env"), []byte("TINT=teal\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "right.env"), []byte("TINT=navy\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	t.Run("inspect", func(t *testing.T) {
		rt, out, errb := reportRT(dir)
		if code := rt.Run([]string{"inspect", "--project-directory", dir}); code != 0 {
			t.Fatalf("code=%d err=%s", code, errb.String())
		}
		blob := out.String()
		if !strings.Contains(blob, "my-application-service-v2") || !strings.Contains(blob, "payment-gateway-worker-01") {
			t.Fatalf("inspect missing names:\n%s", blob)
		}
	})
	t.Run("explain_all", func(t *testing.T) {
		rt, out, errb := reportRT(dir)
		if code := rt.Run([]string{"explain", "--all", "--project-directory", dir}); code != 0 {
			t.Fatalf("code=%d err=%s", code, errb.String())
		}
		blob := out.String()
		for _, id := range []string{
			"services.my-application-service-v2.image",
			"services.payment-gateway-worker-01.image",
			"my-application-service-v2:COLOR",
		} {
			if !strings.Contains(blob, id) {
				t.Fatalf("explain --all missing %q:\n%s", id, blob)
			}
		}
		if strings.Contains(blob, "[redacted]") {
			t.Fatalf("explain --all over-redacted identities:\n%s", blob)
		}
	})
	t.Run("check", func(t *testing.T) {
		rt, out, errb := reportRT(dir)
		code := rt.Run([]string{"check", "--project-directory", dir})
		if code != 0 && code != exitcode.Assertion {
			t.Fatalf("code=%d err=%s", code, errb.String())
		}
		blob := out.String()
		if !strings.Contains(blob, "services.payment-gateway-worker-01.image") {
			t.Fatalf("check missing identity:\n%s", blob)
		}
		if strings.Contains(blob, "[redacted]") {
			t.Fatalf("check over-redacted identity:\n%s", blob)
		}
	})
	t.Run("diff", func(t *testing.T) {
		rt, out, errb := reportRT(dir)
		code := rt.Run([]string{
			"diff", "--project-directory", dir,
			"--left-env-file", filepath.Join(dir, "left.env"),
			"--right-env-file", filepath.Join(dir, "right.env"),
		})
		if code != 0 {
			t.Fatalf("code=%d err=%s", code, errb.String())
		}
		blob := out.String()
		if !strings.Contains(blob, "my-application-service-v2:COLOR") {
			t.Fatalf("diff missing identity:\n%s", blob)
		}
		if strings.Contains(blob, "[redacted]") {
			t.Fatalf("diff over-redacted identity:\n%s", blob)
		}
	})
}

func TestHumanStillRedactsSecretValues(t *testing.T) {
	const probe = "AKIAIOSFODNN7EXAMPLE"
	dir := digitCompose(t, ""+
		"services:\n"+
		"  my-application-service-v2:\n"+
		"    image: alpine\n"+
		"    environment:\n"+
		"      API_TOKEN: "+probe+"\n")
	for _, cmd := range [][]string{
		{"inspect"},
		{"explain", "--all"},
		{"check"},
	} {
		t.Run(strings.Join(cmd, "_"), func(t *testing.T) {
			rt, out, errb := reportRT(dir)
			code := rt.Run(append(append([]string{}, cmd...), "--project-directory", dir))
			if code != 0 && code != exitcode.Assertion {
				t.Fatalf("code=%d err=%s", code, errb.String())
			}
			blob := out.String() + errb.String()
			if strings.Contains(blob, probe) {
				t.Fatalf("%v leaked secret", cmd)
			}
			if cmd[0] != "check" && !strings.Contains(out.String(), "my-application-service-v2") {
				t.Fatalf("%v missing identity", cmd)
			}
		})
	}
}

func TestReportSelfContainedTempProject(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("json code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.report.v0"`) {
		t.Fatal("json missing schema")
	}
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("html code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "<!DOCTYPE html>") {
		t.Fatal("html missing doctype")
	}
}
