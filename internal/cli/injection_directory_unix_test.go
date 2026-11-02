// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

func TestHumanCommandsEscapeDirectoryNewlinesOnUnix(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "first\n::error title=FromDir::forged")
	if err := os.Mkdir(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services: {api: {image: nginx, environment: {NOTE: 'ordinary'}}}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"inspect"}, {"explain", "api:NOTE"}, {"explain", "--all"}, {"check"}, {"differential"}, {"reproduce"}, {"doctor"}} {
		code, out, errs := runIn(t, dir, nil, args...)
		if code != 0 {
			t.Errorf("%v exit=%d stderr=%s", args, code, errs)
		}
		if bad := startsWorkflowCommand(out + errs); len(bad) != 0 {
			t.Errorf("%v: forged workflow commands: %q", args, bad)
		}
	}
}
