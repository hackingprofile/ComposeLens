// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"

	"composelens/internal/safety"
)

// TestOversizedDetectionHelperProcess is not a test: it is the stand-in engine that
// TestDetectionOutputIsBounded runs as a subprocess.
func TestOversizedDetectionHelperProcess(t *testing.T) {
	switch os.Getenv("COMPOSELENS_DETECTION_HELPER") {
	case "stdout":
		fmt.Print(strings.Repeat("x", 5<<20))
		os.Exit(0)
	case "stderr":
		fmt.Fprint(os.Stderr, strings.Repeat("x", 5<<20))
		os.Exit(1)
	}
}

// Detection output is captured with a byte cap and an overflow is a
// typed resource-bound error, like the config adapter.
func TestDetectionOutputIsBounded(t *testing.T) {
	for _, mode := range []string{"stdout", "stderr"} {
		t.Setenv("COMPOSELENS_DETECTION_HELPER", mode)
		d := Detector{Run: func(ctx context.Context, _ string, _ ...string) (string, error) {
			return run(ctx, os.Args[0], "-test.run=TestOversizedDetectionHelperProcess")
		}}
		info := d.Detect()
		if info.Err == nil || !safety.IsResourceBound(info.Err) {
			t.Fatalf("%s: overflow not typed: err=%v state=%s detail=%d bytes", mode, info.Err, info.State, len(info.Detail))
		}
		if len(info.Detail) > MaxDetailBytes || len(info.Version) > 64 {
			t.Fatalf("%s: oversized metadata retained", mode)
		}
	}
}
