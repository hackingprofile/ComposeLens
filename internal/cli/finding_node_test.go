// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
	"composelens/internal/report"
)

type findingNodePackage struct {
	Graph struct {
		Nodes []struct {
			Target string `json:"target"`
			Kind   string `json:"kind"`
		} `json:"nodes"`
	} `json:"graph"`
	Check struct {
		Findings []struct {
			ID        string `json:"id"`
			Target    string `json:"target"`
			Kind      string `json:"kind"`
			GraphNode *struct {
				Target string `json:"target"`
				Kind   string `json:"kind"`
			} `json:"graphNode"`
		} `json:"findings"`
	} `json:"check"`
}

// Every finding in the report data names exactly one graph node,
// for every check lab, so the viewer's source chain can always open.
func TestEveryReportFindingResolvesToOneGraphNode(t *testing.T) {
	labs, err := filepath.Glob(filepath.Join("..", "..", "examples", "check-lab", "*"))
	if err != nil || len(labs) == 0 {
		t.Fatalf("no check labs: %v", err)
	}
	ui := writeProbeProject(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    env_file: app.env\n    environment:\n      COLOR: green\n      REQUIRED: ${UNSET:?provide a value}\n  aux:\n    image: busybox:1.37\n",
		"app.env":      "COLOR=blue\n",
	})
	total := 0
	for _, dir := range append(labs, ui) {
		if st, err := os.Stat(dir); err != nil || !st.IsDir() {
			continue
		}
		rt, out, errb := reportRT(dir)
		if code := rt.Run([]string{"report", "--json", "--no-engine", "--project-directory", dir}); code != exitcode.OK {
			t.Fatalf("%s: code=%d err=%s", dir, code, errb.String())
		}
		var pkg findingNodePackage
		if err := json.Unmarshal(out.Bytes(), &pkg); err != nil {
			t.Fatal(err)
		}
		for _, f := range pkg.Check.Findings {
			total++
			if f.GraphNode == nil {
				t.Errorf("%s: %s %s (%s) has no graphNode", filepath.Base(dir), f.ID, f.Target, f.Kind)
				continue
			}
			n := 0
			for _, node := range pkg.Graph.Nodes {
				if node.Target == f.GraphNode.Target && node.Kind == f.GraphNode.Kind {
					n++
				}
			}
			if n != 1 {
				t.Errorf("%s: %s graphNode %+v matches %d nodes", filepath.Base(dir), f.ID, *f.GraphNode, n)
			}
		}
	}
	if total == 0 {
		t.Fatal("no findings exercised")
	}
}

// The viewer opens the finding's own graph node and announces a
// source chain only when it found one.
func TestViewerAnnouncesOnlyAFoundChain(t *testing.T) {
	page, err := report.HTML(mustReportJSON(t))
	if err != nil {
		t.Fatal(err)
	}
	html := string(page)
	if !strings.Contains(html, "graphNode") {
		t.Error("viewer does not use the finding's graphNode reference")
	}
	if strings.Contains(html, `fillChain(document.getElementById("source-detail"), findNode(target, kind));
  announce("Source chain shown");`) {
		t.Error("viewer announces a source chain without checking that a node was found")
	}
	if !strings.Contains(html, "No source chain") {
		t.Error("viewer has no announcement for a missing chain")
	}
}

func mustReportJSON(t *testing.T) []byte {
	t.Helper()
	dir := filepath.Join("..", "..", "examples", "check-lab", "required-unset")
	rt, out, errb := reportRT(dir)
	if code := rt.Run([]string{"report", "--json", "--no-engine", "--project-directory", dir}); code != exitcode.OK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	return out.Bytes()
}
