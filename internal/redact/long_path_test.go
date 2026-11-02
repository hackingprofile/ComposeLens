// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

// Ordinary long path segments (scratch-style names made of words,
// dates and short hex runs) are provenance, not secrets; a long random run in
// a segment and recognized tokens still are.
func TestOrdinaryLongPathSegmentsAreNotSecrets(t *testing.T) {
	ordinary := []string{
		`C:\Users\dev\AppData\Local\Temp\project_snapshot_12345678_4b7d2e9c\clean\fixtures\diff\env-source\left.env`,
		`/tmp/nightly_checkout_20260117_5c8e2a1f/fixtures/platform/paths-spaces/compose.yaml`,
		`C:\work\my-project-cache-12345678-part-17\compose.override.yaml`,
		`env-file:C:\Users\dev\AppData\Local\Temp\project_snapshot_12345678_4b7d2e9c\left.env`,
	}
	for _, p := range ordinary {
		if LooksLikeSecret(p) || ShouldHideDiagnostic(p) {
			t.Errorf("ordinary path classified secret: %s", p)
		}
	}
	secret := []string{
		"/srv/aB3kL9xQ2mN8pR4t~V6wY1zC5dF7gH0jK/app.env",
		"/srv/ghp_" + strings.Repeat("a", 30) + "/app.env",
		"/srv/aB3kL9xQ2mN8pR4t-V6wY1zC5dF7gH0jK9/app.env",
	}
	for _, p := range secret {
		if !LooksLikeSecret(p) {
			t.Errorf("secret-shaped path segment not classified: %s", p)
		}
	}
}

// A diagnostic is hidden for its file name, read the same on every platform:
// a backslash separates path elements whichever operating system runs the
// command, so a folder name never decides for the file inside it.
func TestDiagnosticPathsReadTheSameOnEveryPlatform(t *testing.T) {
	visible := []string{
		`C:\Users\x\AppData\Local\Temp\TestEarlyErrorsDoNotEchoSecrets001\missing.yaml`,
		`/tmp/TestEarlyErrorsDoNotEchoSecrets001\missing.yaml`,
		`/tmp/run\TestEarlyErrorsDoNotEchoSecrets001\compose.yaml`,
		`D:/work/token-service\compose.override.yaml`,
	}
	for _, p := range visible {
		if ShouldHideDiagnostic(p) {
			t.Errorf("ordinary file name hidden because of its folder: %s", p)
		}
		if DiagnosticLabel(p) != p {
			t.Errorf("label changed for %s", p)
		}
		if b := baseName(p); strings.ContainsAny(b, `/\`) {
			t.Errorf("baseName(%s) = %s, want the last element", p, b)
		}
	}
	hidden := []string{
		`/tmp/run\synthetic-cli-password.env`,
		`C:\tmp\synthetic-cli-password.env`,
		`/srv/app/aB3kL9xQ2mN8pR4tV6wY1zC5dF7gH0jK9.env`,
	}
	for _, p := range hidden {
		if !ShouldHideDiagnostic(p) {
			t.Errorf("secret-shaped file name shown: %s", p)
		}
	}
}
