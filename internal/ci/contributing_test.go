// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// CONTRIBUTING names exactly the CI checks .github/workflows/ci.yml
// can produce: job `test` once per matrix OS.
func TestContributingNamesTheRealChecks(t *testing.T) {
	root := filepath.Join("..", "..")
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var wf struct {
		Name string `yaml:"name"`
		Jobs map[string]struct {
			Name     string `yaml:"name"`
			Strategy struct {
				Matrix struct {
					OS []string `yaml:"os"`
				} `yaml:"matrix"`
			} `yaml:"strategy"`
		} `yaml:"jobs"`
	}
	if err := yaml.Unmarshal(raw, &wf); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{}
	for _, job := range wf.Jobs {
		for _, osName := range job.Strategy.Matrix.OS {
			// A job name that uses the matrix OS is expanded by GitHub; a
			// plain name gets the matrix values appended.
			name := job.Name + " (" + osName + ")"
			if strings.Contains(job.Name, "${{ matrix.os }}") {
				name = strings.ReplaceAll(job.Name, "${{ matrix.os }}", osName)
			}
			want[wf.Name+" / "+name] = true
		}
	}
	if len(want) == 0 {
		t.Fatal("no matrix jobs in ci.yml")
	}
	doc, err := os.ReadFile(filepath.Join(root, "CONTRIBUTING.md"))
	if err != nil {
		t.Fatal(err)
	}
	listed := map[string]bool{}
	for _, m := range regexp.MustCompile("`(ci / [^`]+)`").FindAllStringSubmatch(string(doc), -1) {
		listed[m[1]] = true
	}
	for name := range want {
		if !listed[name] {
			t.Errorf("CONTRIBUTING.md does not list %q", name)
		}
	}
	for name := range listed {
		if !want[name] {
			t.Errorf("CONTRIBUTING.md lists %q, which ci.yml cannot produce", name)
		}
	}
	for _, platform := range []string{"Linux", "macOS", "Windows"} {
		if !strings.Contains(string(doc), platform) {
			t.Errorf("CONTRIBUTING.md does not name the %s CI leg", platform)
		}
	}
}
