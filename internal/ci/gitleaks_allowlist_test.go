// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
)

var syntheticGitHubToken = regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})`)

// TestGitleaksAllowlistCoversSyntheticProbes: every GitHub-token-shaped probe
// in a Go test file is allow-listed in .gitleaks.toml by its exact value, so
// the secret scan stays green on every gitleaks release while a real token
// anywhere else still fails it. A new probe must be added to the allowlist.
func TestGitleaksAllowlistCoversSyntheticProbes(t *testing.T) {
	root := filepath.Join("..", "..")
	cfg, err := os.ReadFile(filepath.Join(root, ".gitleaks.toml"))
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, m := range regexp.MustCompile(`'''\^([A-Za-z0-9_]+)\$'''`).FindAllStringSubmatch(string(cfg), -1) {
		allowed[m[1]] = true
	}
	probes := map[string][]string{}
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(p, "_test.go") {
			return err
		}
		raw, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		for _, tok := range syntheticGitHubToken.FindAllString(string(raw), -1) {
			probes[tok] = append(probes[tok], filepath.ToSlash(p))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(probes) == 0 {
		t.Fatal("no synthetic probes found; the scan pattern is wrong")
	}
	var missing []string
	for tok, files := range probes {
		if !allowed[tok] {
			missing = append(missing, tok+" ("+files[0]+")")
		}
	}
	sort.Strings(missing)
	for _, m := range missing {
		t.Errorf(".gitleaks.toml does not allow-list the synthetic probe %s", m)
	}
}

func TestSyntheticTokensStayInAllowedTestFiles(t *testing.T) {
	root := filepath.Join("..", "..")
	export, err := os.ReadFile(filepath.Join(root, "scripts", "export-release.ps1"))
	if err != nil {
		t.Fatal(err)
	}
	list := regexp.MustCompile(`(?s)\$Allow = @\((.*?)\)`).FindSubmatch(export)
	if len(list) != 2 {
		t.Fatal("export allowlist missing")
	}
	checked := 0
	for _, m := range regexp.MustCompile(`"([^"]+)"`).FindAllSubmatch(list[1], -1) {
		entry := string(m[1])
		// The scanner configuration defines the exact synthetic values.
		if entry == ".gitleaks.toml" {
			continue
		}
		err := filepath.WalkDir(filepath.Join(root, entry), func(p string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return err
			}
			rel, err := filepath.Rel(root, p)
			if err != nil {
				return err
			}
			rel = filepath.ToSlash(rel)
			if strings.HasPrefix(rel, "internal/") && strings.HasSuffix(rel, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			checked++
			if syntheticGitHubToken.Match(raw) {
				t.Errorf("%s contains a synthetic credential outside allowed test files", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if checked < 100 {
		t.Fatalf("only checked %d public files", checked)
	}
}
