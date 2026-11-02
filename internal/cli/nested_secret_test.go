// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/engine"
	"composelens/internal/evidence"
)

// runIn runs the CLI in dir with an explicit environment and returns the exit
// code and combined output.
func runIn(t *testing.T, dir string, environ []string, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Environ: environ,
		Cwd:     dir,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	code := rt.Run(args)
	return code, out.String(), errb.String()
}

func writeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// outputCommands are the commands that render values.
var outputCommands = [][]string{
	{"inspect"},
	{"inspect", "--json"},
	{"explain", "--all"},
	{"explain", "--all", "--json"},
	{"report", "--json", "--no-engine"},
	{"report", "--html", "--no-engine"},
}

func assertNoneLeak(t *testing.T, dir string, secrets []string) {
	t.Helper()
	for _, args := range outputCommands {
		code, out, errs := runIn(t, dir, nil, args...)
		if code != 0 {
			t.Errorf("%v: exit %d, want 0; stderr=%s", args, code, errs)
		}
		for _, s := range secrets {
			if strings.Contains(out, s) || strings.Contains(errs, s) {
				t.Errorf("%v printed secret %q", args, s)
			}
		}
	}
}

func TestSecretUnderSecretNamedMappingIsWithheld(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "x-credentials:\n" +
			"  api_token:\n" +
			"    value: nestedleak123456\n" +
			"services:\n" +
			"  api:\n" +
			"    image: nginx\n" +
			"    x-auth:\n" +
			"      password:\n" +
			"        current: nestedleak789012\n",
	})
	assertNoneLeak(t, dir, []string{"nestedleak123456", "nestedleak789012"})
	// The ordinary value stays readable.
	_, out, _ := runIn(t, dir, nil, "inspect")
	if !strings.Contains(out, "value=nginx") {
		t.Errorf("ordinary value hidden:\n%s", out)
	}
}

func TestSecretUnderSecretNamedMappingInterpolatedIsWithheld(t *testing.T) {
	dir := writeProject(t, map[string]string{
		".env": "INNER=interpnested4242\n",
		"compose.yaml": "services:\n" +
			"  api:\n" +
			"    image: nginx\n" +
			"    x-auth:\n" +
			"      password:\n" +
			"        current: ${INNER}\n",
	})
	assertNoneLeak(t, dir, []string{"interpnested4242"})
}

func TestComposeSecretReferencesStayReadable(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n" +
			"  api:\n" +
			"    image: nginx\n" +
			"    secrets:\n" +
			"      - source: db_password\n" +
			"        target: dbpass\n" +
			"secrets:\n" +
			"  db_password:\n" +
			"    file: ./db_password.txt\n",
		"db_password.txt": "x\n",
	})
	_, out, _ := runIn(t, dir, nil, "inspect")
	for _, want := range []string{"value=./db_password.txt", "value=db_password", "value=dbpass"} {
		if !strings.Contains(out, want) {
			t.Errorf("secret reference %q hidden:\n%s", want, out)
		}
	}
}
