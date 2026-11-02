// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestShellDetectionReportsOnlyTheName(t *testing.T) {
	for _, goos := range []string{"linux", "darwin"} {
		shell, _ := detectShellUsing(goos, func(key string) string {
			if key == "SHELL" {
				return "/opt/custom-tools/private-dir/bin/zsh"
			}
			return ""
		})
		if shell != "zsh" || strings.ContainsAny(shell, `/\`) {
			t.Errorf("%s shell exposes its path: %q", goos, shell)
		}
	}
}
