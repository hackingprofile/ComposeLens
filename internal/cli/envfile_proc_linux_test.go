// SPDX-License-Identifier: Apache-2.0

//go:build linux

package cli

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

const procProbe = "4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e"

// TestHelperRunInEnv is not a test on its own: the parent test re-runs the
// test binary with a synthetic environment so /proc/self/environ holds only
// what the parent chose.
func TestHelperRunInEnv(t *testing.T) {
	if os.Getenv("COMPOSELENS_HELPER_DIR") == "" {
		t.Skip("helper process only")
	}
	args := strings.Split(os.Getenv("COMPOSELENS_HELPER_ARGS"), "\x1f")
	args = append(args, "--project-directory", os.Getenv("COMPOSELENS_HELPER_DIR"))
	os.Exit(Run(args, os.Stdout, os.Stderr, os.Environ()))
}

func TestEnvFileProcSelfEnvironIsNotPrinted(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  api:\n    image: nginx\n    env_file: /proc/self/environ\n",
	})
	for _, args := range outputCommands {
		cmd := exec.Command(os.Args[0], "-test.run=^TestHelperRunInEnv$")
		cmd.Env = []string{
			"PATH=/usr/bin:/bin",
			"OPTS=-Xmx1g -Dy=1",
			"RUNNER_SESSION_TOKEN=" + procProbe,
			"COMPOSELENS_HELPER_DIR=" + dir,
			"COMPOSELENS_HELPER_ARGS=" + strings.Join(args, "\x1f"),
		}
		out, err := cmd.CombinedOutput()
		code := 0
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			code = ee.ExitCode()
		} else if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(out), procProbe) {
			t.Errorf("%v printed the process environment", args)
		}
		if code != exitcode.Input || !strings.Contains(string(out), "input-not-regular-file") {
			t.Errorf("%v: exit %d, want %d with input-not-regular-file:\n%s", args, code, exitcode.Input, out)
		}
	}
}
