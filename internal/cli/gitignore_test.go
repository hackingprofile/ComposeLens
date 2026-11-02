// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

type ignoreRule struct {
	re      *regexp.Regexp
	negate  bool
	dirOnly bool
}

// gitignoreRules is a small matcher for the .gitignore features this repository
// uses: comments, ! negation, trailing-slash directory patterns, a leading
// or inner slash anchoring to the root, and * ** ? globs. (No Git is run.)
func gitignoreRules(t *testing.T, text string) []ignoreRule {
	t.Helper()
	var out []ignoreRule
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimRight(line, " ")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		r := ignoreRule{}
		if strings.HasPrefix(line, "!") {
			r.negate = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			r.dirOnly = true
			line = strings.TrimSuffix(line, "/")
		}
		anchored := strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		var b strings.Builder
		for i := 0; i < len(line); i++ {
			switch c := line[i]; {
			case c == '*' && i+1 < len(line) && line[i+1] == '*':
				if i+2 < len(line) && line[i+2] == '/' {
					b.WriteString(`(?:.*/)?`)
					i += 2
				} else {
					b.WriteString(`.*`)
					i++
				}
			case c == '*':
				b.WriteString(`[^/]*`)
			case c == '?':
				b.WriteString(`[^/]`)
			default:
				b.WriteString(regexp.QuoteMeta(string(c)))
			}
		}
		prefix := `^(?:.*/)?`
		if anchored {
			prefix = `^`
		}
		r.re = regexp.MustCompile(prefix + b.String() + `$`)
		out = append(out, r)
	}
	return out
}

// ignored reports whether a slash path (a file) is ignored: a matching rule
// on the file or on any parent directory; the last matching rule wins, and a
// file under an ignored directory cannot be re-included.
func ignored(rules []ignoreRule, path string) bool {
	parts := strings.Split(path, "/")
	for i := 1; i < len(parts); i++ {
		dir := strings.Join(parts[:i], "/")
		state := false
		for _, r := range rules {
			if r.re.MatchString(dir) {
				state = !r.negate
			}
		}
		if state {
			return true
		}
	}
	state := false
	for _, r := range rules {
		if !r.dirOnly && r.re.MatchString(path) {
			state = !r.negate
		}
	}
	return state
}

// Local operator env files, generated reports and support bundles
// are ignored; public lab, example and fixture data stays eligible.
func TestGitignoreKeepsOperatorFilesOut(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, ".gitignore"))
	if err != nil {
		t.Fatal(err)
	}
	rules := gitignoreRules(t, string(raw))
	mustIgnore := []string{
		".env", ".env.production", "app.env", "deploy/.env", "deploy/secrets.env", "deploy/.env.local",
		"report.html", "report.json", "out/report.html", "composelens-support.json", "composelens-check.json",
		"composelens-check.sarif", "composelens-check.md", "composelens-annotations.txt",
		".tools/go/bin/go.exe", ".local/notes.md", "composelens.exe", "dist/composelens/README.md",
	}
	for _, p := range mustIgnore {
		if !ignored(rules, p) {
			t.Errorf("%s is not ignored", p)
		}
	}
	mustKeep := []string{
		"examples/graph-lab/.env", "examples/graph-lab/extra.env", "examples/precedence-lab/.env",
		"fixtures/diff/env-source/left.env", "fixtures/interp/.env.app", "testdata/golden/report.json",
		"internal/cli/run.go", "README.md", "docs/report.md",
	}
	for _, p := range mustKeep {
		if ignored(rules, p) {
			t.Errorf("%s is ignored but must stay in the public tree", p)
		}
	}
	// Every file of the public tree (except toolchains, operator records, binaries and
	// build outputs such as an export under dist/) stays eligible.
	err = filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, p)
		rel = filepath.ToSlash(rel)
		if d.IsDir() {
			// Only the published top-level folders; toolchains, operator records and
			// build outputs live elsewhere.
			if !strings.Contains(rel, "/") && rel != "." && !publicDirs[rel] {
				return filepath.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(rel, ".exe") {
			return nil
		}
		if ignored(rules, rel) {
			t.Errorf("public file %s would be ignored", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// publicDirs are the top-level folders of the published source tree (the
// folders scripts/export-release.ps1 copies).
var publicDirs = map[string]bool{
	".github": true, "cmd": true, "docs": true, "examples": true, "fixtures": true,
	"internal": true, "schemas": true, "scripts": true, "testdata": true,
}
