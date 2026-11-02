// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"testing"
)

// How the shell is detected depends on the platform (SHELL on Linux and
// macOS is proven; Windows is inferred), so the stable goldens do not pin it.
func TestStableGoldensIgnoreShellDetectionCertainty(t *testing.T) {
	windows := []byte("{\n    \"shell\": \"pwsh\",\n    \"certainty\": \"inferred\"\n  }")
	linux := []byte("{\n    \"shell\": \"/bin/bash\",\n    \"certainty\": \"proven\"\n  }")
	if !bytes.Equal(stabilize(windows, "/p"), stabilize(linux, "/p")) {
		t.Errorf("goldens differ by shell detection:\n%s\n%s", stabilize(windows, "/p"), stabilize(linux, "/p"))
	}
}
