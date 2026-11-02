// SPDX-License-Identifier: Apache-2.0

// Package testenv holds helpers for tests that need an external tool.
package testenv

import (
	"os"
	"os/exec"
	"testing"
)

// EnvRequireDocker makes a missing Docker CLI a test failure instead of a
// skip. Set it to 1 where Docker is expected (the Windows CI job does).
const EnvRequireDocker = "COMPOSELENS_REQUIRE_DOCKER"

// RequireDocker skips the calling test when no Docker CLI is on PATH, unless
// COMPOSELENS_REQUIRE_DOCKER=1, in which case a missing CLI fails the test.
// Live tests run `docker compose config`, which is client-side and needs no
// daemon.
func RequireDocker(t testing.TB) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err == nil {
		return
	}
	if os.Getenv(EnvRequireDocker) == "1" {
		t.Fatal("docker CLI required (" + EnvRequireDocker + "=1) but not on PATH")
	}
	t.Skip("docker CLI not on PATH; live engine test skipped (set " + EnvRequireDocker + "=1 to require it)")
}
