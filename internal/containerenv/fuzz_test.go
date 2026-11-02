// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/safety"
)

func FuzzEnvFileDoesNotPanic(f *testing.F) {
	f.Add("FOO=bar\n")
	f.Add("export Q=1\n")
	f.Add("FOO=\"a\\nb\"\n")
	f.Add("# comment\n")
	f.Fuzz(func(t *testing.T, body string) {
		if len(body) > 32*1024 {
			body = body[:32*1024]
		}
		defer func() {
			if rec := recover(); rec != nil {
				t.Fatalf("panic: %v", rec)
			}
		}()
		dir := t.TempDir()
		p := filepath.Join(dir, "x.env")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _ = readEnvFile(p, "", nil, safety.NewBudget())
	})
}
