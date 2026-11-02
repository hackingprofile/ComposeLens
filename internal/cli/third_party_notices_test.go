// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func readText(t *testing.T, p string) string {
	t.Helper()
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return strings.ReplaceAll(string(raw), "\r\n", "\n")
}

// requiredModules returns "path@version" for every require in go.mod.
func requiredModules(t *testing.T, gomod string) []string {
	t.Helper()
	var out []string
	in := false
	sc := bufio.NewScanner(strings.NewReader(readText(t, gomod)))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "require (":
			in = true
			continue
		case in && line == ")":
			in = false
			continue
		case strings.HasPrefix(line, "require "):
			line = strings.TrimSpace(strings.TrimPrefix(line, "require "))
		case !in:
			continue
		}
		f := strings.Fields(line)
		if len(f) >= 2 {
			out = append(out, f[0]+"@"+f[1])
		}
	}
	return out
}

// The single-binary distribution carries the notices of the code
// linked into it: every required module, and the Go standard library.
func TestThirdPartyNoticesCoverLinkedModules(t *testing.T) {
	root := filepath.Join("..", "..")
	notices := readText(t, filepath.Join(root, "THIRD_PARTY_NOTICES.md"))
	mods := requiredModules(t, filepath.Join(root, "go.mod"))
	if len(mods) == 0 {
		t.Fatal("no required modules parsed")
	}
	for _, m := range mods {
		if !strings.Contains(notices, m) {
			t.Errorf("THIRD_PARTY_NOTICES.md does not list %s", m)
		}
		cache := os.Getenv("GOMODCACHE")
		if cache == "" {
			if home, err := os.UserHomeDir(); err == nil {
				cache = filepath.Join(home, "go", "pkg", "mod")
			}
		}
		for _, name := range []string{"LICENSE", "NOTICE"} {
			p := filepath.Join(cache, filepath.FromSlash(m), name)
			if _, err := os.Stat(p); err != nil {
				continue // module cache not present: the listing check above still applies
			}
			if text := strings.TrimSpace(readText(t, p)); !strings.Contains(notices, text) {
				t.Errorf("THIRD_PARTY_NOTICES.md does not reproduce %s %s verbatim", m, name)
			}
		}
	}
	if !strings.Contains(notices, "The Go Authors") {
		t.Error("THIRD_PARTY_NOTICES.md lacks the Go licence")
	}
	if p := filepath.Join(goRoot(), "LICENSE"); fileExistsCLI(p) {
		if text := strings.TrimSpace(readText(t, p)); !strings.Contains(notices, text) {
			t.Error("THIRD_PARTY_NOTICES.md does not reproduce the Go LICENSE verbatim")
		}
	}
	for _, ref := range []string{"NOTICE", filepath.Join("docs", "distribution.md")} {
		if !strings.Contains(readText(t, filepath.Join(root, ref)), "THIRD_PARTY_NOTICES.md") {
			t.Errorf("%s does not reference THIRD_PARTY_NOTICES.md", ref)
		}
	}
}

func fileExistsCLI(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// goRoot is the GOROOT of the go command that runs the tests ("go env
// GOROOT"); empty when it cannot be asked.
func goRoot() string {
	out, err := exec.Command("go", "env", "GOROOT").Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}
