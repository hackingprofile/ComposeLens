// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// minimumGo is the oldest Go release the module may name. Go fixes security
// issues only in its two newest major releases, so raise this floor when a
// new major release ships.
var minimumGo = [3]int{1, 27, 3}

// goDirective returns go.mod's go line as "1.27.3" and its three numbers.
func goDirective(t *testing.T) (string, [3]int) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	m := regexp.MustCompile(`(?m)^go (\d+)\.(\d+)(?:\.(\d+))?\s*$`).FindStringSubmatch(string(raw))
	if m == nil {
		t.Fatal("go.mod has no go directive")
	}
	var v [3]int
	for i := range v {
		v[i], _ = strconv.Atoi(m[i+1])
	}
	if m[3] == "" {
		t.Errorf("go.mod go %s.%s: name an exact release (1.N.P) so setup-go installs a patched toolchain", m[1], m[2])
	}
	return strings.TrimSpace(strings.TrimPrefix(m[0], "go ")), v
}

// TestGoDirectiveIsSupported keeps the module on a Go release that still
// receives security fixes; the Action builds users' binaries with it, and
// setup-go installs exactly this release through go-version-file.
func TestGoDirectiveIsSupported(t *testing.T) {
	text, v := goDirective(t)
	for i := range v {
		if v[i] != minimumGo[i] {
			if v[i] < minimumGo[i] {
				t.Errorf("go.mod go %s: want %d.%d.%d or newer", text, minimumGo[0], minimumGo[1], minimumGo[2])
			}
			break
		}
	}
}

// TestGoReleaseIsStatedConsistently: every place that names the Go release
// (docs, notices, the bug template, the licence scanner job) names go.mod's.
func TestGoReleaseIsStatedConsistently(t *testing.T) {
	want, _ := goDirective(t)
	root := filepath.Join("..", "..")
	for _, f := range []string{
		filepath.Join("docs", "compatibility.md"),
		"THIRD_PARTY_NOTICES.md",
		"CONTRIBUTING.md",
		filepath.Join(".github", "ISSUE_TEMPLATE", "bug.yml"),
		filepath.Join(".github", "workflows", "license-scan.yml"),
	} {
		raw, err := os.ReadFile(filepath.Join(root, f))
		if err != nil {
			t.Fatal(err)
		}
		found := regexp.MustCompile(`\bGo:? "?(1\.\d+\.\d+)`).FindAllStringSubmatch(string(raw), -1)
		found = append(found, regexp.MustCompile(`go-version: "(1\.\d+\.\d+)"`).FindAllStringSubmatch(string(raw), -1)...)
		if len(found) == 0 {
			t.Errorf("%s names no Go release; want %s", f, want)
		}
		for _, got := range found {
			if got[1] != want {
				t.Errorf("%s names Go %s; go.mod names %s", f, got[1], want)
			}
		}
	}
}

// TestLintRunsGolangciV2: the lint step runs golangci-lint v2 through a
// pinned action release that supports it, against a v2 configuration.
func TestLintRunsGolangciV2(t *testing.T) {
	root := filepath.Join("..", "..")
	var cfg struct {
		Version string `yaml:"version"`
		Linters struct {
			Enable []string `yaml:"enable"`
		} `yaml:"linters"`
		Formatters struct {
			Enable []string `yaml:"enable"`
		} `yaml:"formatters"`
	}
	raw, err := os.ReadFile(filepath.Join(root, ".golangci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Version != "2" {
		t.Errorf(".golangci.yml version %q: want \"2\"", cfg.Version)
	}
	enabled := map[string]bool{}
	for _, l := range append(cfg.Linters.Enable, cfg.Formatters.Enable...) {
		enabled[l] = true
	}
	for _, l := range []string{"errcheck", "govet", "ineffassign", "staticcheck", "unused", "misspell", "unconvert", "unparam", "gocritic", "revive", "gofmt", "goimports"} {
		if !enabled[l] {
			t.Errorf(".golangci.yml does not enable %s", l)
		}
	}
	path := filepath.Join(root, ".github", "workflows", "ci.yml")
	ci := loadHygiene(t, path)
	ciRaw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, j := range ci.Jobs {
		for _, st := range j.Steps {
			if !strings.HasPrefix(st.Uses, "golangci/golangci-lint-action@") {
				continue
			}
			found = true
			if !regexp.MustCompile(`^v2\.\d+\.\d+$`).MatchString(st.With["version"]) {
				t.Errorf("ci.yml lint version %q: want an exact golangci-lint v2 release", st.With["version"])
			}
			sha := strings.TrimPrefix(st.Uses, "golangci/golangci-lint-action@")
			if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sha) {
				t.Errorf("ci.yml lint action %q: want a full commit SHA", st.Uses)
			}
			tag := regexp.MustCompile(`golangci-lint-action@` + regexp.QuoteMeta(sha) + ` # v(\d+)\.`).FindSubmatch(ciRaw)
			if tag == nil {
				t.Error("ci.yml lint action pin has no version comment")
			} else if major, _ := strconv.Atoi(string(tag[1])); major < 7 {
				t.Errorf("ci.yml lint action v%s runs golangci-lint v1 only; v7 or later runs v2", tag[1])
			}
		}
	}
	if !found {
		t.Error("ci.yml has no golangci-lint step")
	}
}

type hygieneStep struct {
	Uses string            `yaml:"uses"`
	Run  string            `yaml:"run"`
	With map[string]string `yaml:"with"`
}

type hygieneJob struct {
	Permissions map[string]string `yaml:"permissions"`
	Strategy    struct {
		Matrix struct {
			OS []string `yaml:"os"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []hygieneStep `yaml:"steps"`
}

type hygieneWorkflow struct {
	Permissions map[string]string     `yaml:"permissions"`
	Jobs        map[string]hygieneJob `yaml:"jobs"`
	Runs        struct {
		Steps []hygieneStep `yaml:"steps"`
	} `yaml:"runs"`
}

func loadHygiene(t *testing.T, path string) hygieneWorkflow {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var wf hygieneWorkflow
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return wf
}

// TestWorkflowHygiene: checkouts do not persist credentials, run: scripts
// take no ${{ }} expressions (inputs go through env:), CodeQL can read the
// workflow run, and ci.yml tests on Linux, macOS and Windows.
func TestWorkflowHygiene(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	files = append(files, filepath.Join("..", "..", "action.yml"))
	for _, f := range files {
		name := filepath.Base(f)
		wf := loadHygiene(t, f)
		steps := wf.Runs.Steps
		for _, j := range wf.Jobs {
			steps = append(steps, j.Steps...)
		}
		for _, st := range steps {
			if strings.HasPrefix(strings.TrimSpace(st.Uses), "actions/checkout@") && st.With["persist-credentials"] != "false" {
				t.Errorf("%s: actions/checkout without persist-credentials: false", name)
			}
			if strings.Contains(st.Run, "${{") {
				t.Errorf("%s: a run: script contains a ${{ }} expression; pass it through env:", name)
			}
		}
	}
	codeql := loadHygiene(t, filepath.Join("..", "..", ".github", "workflows", "codeql.yml"))
	read := codeql.Permissions["actions"] == "read"
	for _, j := range codeql.Jobs {
		if j.Permissions["actions"] == "read" {
			read = true
		}
	}
	if !read {
		t.Error("codeql.yml: permissions lack actions: read")
	}
	ci := loadHygiene(t, filepath.Join("..", "..", ".github", "workflows", "ci.yml"))
	want := map[string]bool{"ubuntu-latest": false, "macos-latest": false, "windows-latest": false}
	for _, j := range ci.Jobs {
		for _, os := range j.Strategy.Matrix.OS {
			if _, ok := want[os]; ok {
				want[os] = true
			}
		}
	}
	for os, ok := range want {
		if !ok {
			t.Errorf("ci.yml: no %s leg", os)
		}
	}
}
