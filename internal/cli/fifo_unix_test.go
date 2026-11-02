// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import (
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"composelens/internal/exitcode"
)

func runWithin(t *testing.T, d time.Duration, dir string, args ...string) (int, string) {
	t.Helper()
	type res struct {
		code int
		errs string
	}
	done := make(chan res, 1)
	go func() {
		code, _, errs := runIn(t, dir, nil, args...)
		done <- res{code, errs}
	}()
	select {
	case r := <-done:
		return r.code, r.errs
	case <-time.After(d):
		t.Fatalf("%v did not finish within %s (blocked on a FIFO)", args, d)
		return 0, ""
	}
}

func TestComposeFileFIFOIsRefusedWithoutHanging(t *testing.T) {
	dir := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(dir, "compose.yaml"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	code, errs := runWithin(t, 10*time.Second, dir, "inspect")
	if code != exitcode.Input || !strings.Contains(errs, "input-not-regular-file") {
		t.Errorf("exit %d stderr=%s, want exit 3 input-not-regular-file", code, errs)
	}
}

func TestEnvFileFIFOIsRefusedWithoutHanging(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  api:\n    image: nginx\n    env_file: pipe.env\n",
	})
	if err := syscall.Mkfifo(filepath.Join(dir, "pipe.env"), 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	code, errs := runWithin(t, 10*time.Second, dir, "inspect")
	if code != exitcode.Input || !strings.Contains(errs, "input-not-regular-file") {
		t.Errorf("exit %d stderr=%s, want exit 3 input-not-regular-file", code, errs)
	}
}
