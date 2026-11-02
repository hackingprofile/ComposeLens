// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"testing"
)

// The report anchors embed the live engine section; the installed Compose
// release must not change the anchored bytes.
func TestReportAnchorIgnoresTheEngineRelease(t *testing.T) {
	a := []byte(`{"differential": {"engineVersion": "v5.4.0", "rows": []}}`)
	b := []byte(`{"differential": {"engineVersion": "v2.40.3", "rows": []}}`)
	for _, html := range []bool{false, true} {
		if !bytes.Equal(stabilizeReport(a, "/p", html), stabilizeReport(b, "/p", html)) {
			t.Errorf("html=%v: anchors differ only by the engine release", html)
		}
	}
}
