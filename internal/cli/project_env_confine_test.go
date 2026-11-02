// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func assertProjectEnvWithheld(t *testing.T, proj, source string, selection []string) {
	t.Helper()
	for _, args := range outputCommands {
		cmd := append(append([]string{}, args...), selection...)
		code, out, errs := runIn(t, proj, nil, cmd...)
		if code != 0 && code != 6 {
			t.Errorf("%v: code=%d stderr=%s", cmd, code, errs)
		}
		for _, value := range outsideValues {
			if strings.Contains(out+errs, value) {
				t.Errorf("%v exposed outside value", cmd)
			}
		}
	}
	code, out, errs := runIn(t, proj, nil, append([]string{"inspect"}, selection...)...)
	for _, want := range []string{"OUTSIDE_PLAIN", "outside the project directory", source, ":1"} {
		if code != 0 || !strings.Contains(out, want) {
			t.Errorf("inspect must retain %q: code=%d\n%s\n%s", want, code, out, errs)
		}
	}
}

func TestSelectedEnvFileOutsideProjectIsWithheld(t *testing.T) {
	proj, outside := outsideLayout(t, "services: {api: {image: nginx, environment: {V: '${OUTSIDE_PLAIN}', OPTS: '${OUTSIDE_OPTS}'}}}\n")
	assertProjectEnvWithheld(t, proj, "outside.env", []string{"--env-file", outside})
}

func TestProjectEnvSymlinkOutsideIsWithheld(t *testing.T) {
	for _, serviceFile := range []bool{false, true} {
		compose := "services: {api: {image: nginx, environment: {V: '${OUTSIDE_PLAIN}', OPTS: '${OUTSIDE_OPTS}'}}}\n"
		if serviceFile {
			compose = "services: {api: {image: nginx, env_file: .env}}\n"
		}
		proj, outside := outsideLayout(t, compose)
		if err := os.Symlink(outside, filepath.Join(proj, ".env")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		assertProjectEnvWithheld(t, proj, ".env", nil)
		assertProjectEnvWithheld(t, proj, ".env", []string{"--env-file", ".env"})
	}
}
