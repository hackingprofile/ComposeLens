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

type workflow struct {
	Permissions map[string]string `yaml:"permissions"`
	Jobs        map[string]struct {
		Permissions map[string]string `yaml:"permissions"`
		Steps       []struct {
			Uses string            `yaml:"uses"`
			Run  string            `yaml:"run"`
			With map[string]string `yaml:"with"`
		} `yaml:"steps"`
	} `yaml:"jobs"`
}

var (
	pinnedUses  = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}$`)
	dockerUses  = regexp.MustCompile(`^docker://[^@]+@sha256:[0-9a-f]{64}$`)
	goRunModule = regexp.MustCompile(`go run ([^\s@]+)@(\S+)`)
	semverTag   = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Actions replaced by pinned steps: at the pinned SHA,
// apache/skywalking-eyes/dependency runs actions/setup-go@v6 (a mutable tag).
// The header action of the same repository is replaced too, so the licence
// job has one immutable path (it was not separately shown to be mutable).
var mutableComposites = []string{"apache/skywalking-eyes/dependency@", "apache/skywalking-eyes/header@", "apache/skywalking-eyes@"}

// Every workflow step runs immutable code (full-SHA action pins,
// digest-pinned images, module-versioned `go run`), and write permissions are
// granted only where a step uses them.
func TestWorkflowsPinnedAndLeastPrivilege(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("..", "..", ".github", "workflows", "*.yml"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no workflows: %v", err)
	}
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var wf workflow
		if err := yaml.Unmarshal(raw, &wf); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		name := filepath.Base(f)
		uses := map[string]bool{}
		publish := false
		for _, job := range wf.Jobs {
			for _, st := range job.Steps {
				u := strings.TrimSpace(st.Uses)
				if st.With["publish_results"] == "true" {
					publish = true
				}
				for _, m := range goRunModule.FindAllStringSubmatch(st.Run, -1) {
					if !semverTag.MatchString(m[2]) {
						t.Errorf("%s: go run %s@%s is not pinned to a released module version", name, m[1], m[2])
					}
				}
				if u == "" || strings.HasPrefix(u, "./") {
					continue
				}
				uses[u] = true
				switch {
				case strings.HasPrefix(u, "docker://"):
					if !dockerUses.MatchString(u) {
						t.Errorf("%s: image %q is not digest-pinned", name, u)
					}
				case !pinnedUses.MatchString(u):
					t.Errorf("%s: %q is not pinned to a full commit SHA", name, u)
				}
				for _, c := range mutableComposites {
					if strings.HasPrefix(u, c) {
						t.Errorf("%s: %q runs mutable nested actions; use pinned steps instead", name, u)
					}
				}
			}
		}
		perms := map[string]string{}
		for k, v := range wf.Permissions {
			perms[k] = v
		}
		for _, job := range wf.Jobs {
			for k, v := range job.Permissions {
				perms[k] = v
			}
		}
		for scope, level := range perms {
			if level != "write" {
				continue
			}
			used := false
			switch scope {
			case "security-events":
				for u := range uses {
					if strings.HasPrefix(u, "github/codeql-action/analyze@") || strings.HasPrefix(u, "github/codeql-action/upload-sarif@") {
						used = true
					}
				}
			case "id-token":
				used = publish
			}
			if !used {
				t.Errorf("%s: %s: write is granted but no step uses it", name, scope)
			}
		}
	}
}
