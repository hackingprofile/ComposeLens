// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestPowerShellScriptsArePortable: scripts/*.ps1 run under pwsh on Linux
// and macOS as well as under Windows PowerShell, so they use no cmd.exe, no
// Windows-only executable or environment variable, and no backslash path
// literals. Windows-only API calls sit behind an OS check.
func TestPowerShellScriptsArePortable(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", "scripts", "*.ps1"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no scripts: %v", err)
	}
	rules := []struct {
		re   *regexp.Regexp
		what string
	}{
		{regexp.MustCompile(`(?i)\bcmd(\.exe)?\s+/c\b`), "runs cmd.exe"},
		{regexp.MustCompile(`(?i)&\s*powershell(\.exe)?\b|^\s*powershell(\.exe)?\s+-`), "starts Windows PowerShell by name"},
		{regexp.MustCompile(`(?i)\$env:(TEMP|TMP|USERPROFILE|APPDATA|LOCALAPPDATA|SystemRoot)\b`), "reads a Windows-only environment variable"},
		{regexp.MustCompile(`(?i)Join-Path\b[^\n#]*"[^"\n]*\\[^"\n]*"`), "joins a path with a backslash literal"},
		{regexp.MustCompile(`TrimEnd\('\\'\)`), "trims only a backslash separator"},
		{regexp.MustCompile(`'\\dist\\'|"\\dist\\"`), "tests a path with backslash separators"},
		{regexp.MustCompile(`"composelens\.exe"`), "always names the binary composelens.exe"},
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		name := filepath.Base(f)
		for i, line := range strings.Split(string(raw), "\n") {
			code := line
			if strings.HasPrefix(strings.TrimSpace(code), "#") {
				continue
			}
			for _, r := range rules {
				if r.re.MatchString(code) {
					t.Errorf("%s:%d %s: %s", name, i+1, r.what, strings.TrimSpace(line))
				}
			}
		}
		if strings.Contains(string(raw), "kernel32") && !strings.Contains(string(raw), "$onWindows") {
			t.Errorf("%s: calls kernel32 without an OS check", name)
		}
	}
}
