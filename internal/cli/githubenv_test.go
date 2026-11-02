// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

// clearGitHubEnv runs a test as if outside GitHub Actions: on a runner these
// variables are always set, and they change annotation paths and where the
// summary and artifacts are written.
func clearGitHubEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"GITHUB_WORKSPACE", "GITHUB_STEP_SUMMARY",
		"COMPOSELENS_JSON_PATH", "COMPOSELENS_SARIF_PATH", "COMPOSELENS_GITHUB_SUMMARY", "COMPOSELENS_FAIL_ON",
	} {
		t.Setenv(k, "")
	}
}
