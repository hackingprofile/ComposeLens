// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

// examples/graph-lab/README.md describes the chain the lab really
// produces: --env-file extra.env replaces the project .env (it is not read,
// so it cannot be a shadowed loser); overlay.env COLOR is shadowed.
func TestGraphLabReadmeMatchesTheRealChain(t *testing.T) {
	lab := filepath.Join("..", "..", "examples", "graph-lab")
	abs, err := filepath.Abs(lab)
	if err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(abs)
	if code := rt.Run([]string{"explain", "--all", "--env-file", "extra.env", "--json", "--project-directory", abs}); code != exitcode.OK {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var g struct {
		Nodes []struct {
			Target      string `json:"target"`
			ShadowChain []struct {
				Role   string `json:"role"`
				Stage  string `json:"stage"`
				Source string `json:"source"`
			} `json:"shadowChain"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(out.Bytes(), &g); err != nil {
		t.Fatal(err)
	}
	var sources []string
	worker := false
	for _, n := range g.Nodes {
		if n.Target == "worker" {
			worker = true
		}
		if n.Target != "web:COLOR" {
			continue
		}
		for _, l := range n.ShadowChain {
			sources = append(sources, l.Role+" "+l.Stage+" "+filepath.Base(l.Source))
		}
	}
	chain := strings.Join(sources, "; ")
	if strings.Contains(chain, " .env") {
		t.Errorf("project .env appears in the web:COLOR chain: %s", chain)
	}
	for _, want := range []string{"extra.env", "shadowed container-environment overlay.env"} {
		if !strings.Contains(chain, want) {
			t.Errorf("chain lacks %q: %s", want, chain)
		}
	}
	if !worker {
		t.Error("worker missing from the graph")
	}
	raw, err := os.ReadFile(filepath.Join(lab, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	readme := string(raw)
	if strings.Contains(readme, "`.env` `TINT` shadowed") {
		t.Error("README still expects a shadowed project .env TINT")
	}
	if !strings.Contains(readme, "replaces") || !strings.Contains(readme, "`overlay.env` `COLOR` shadowed") {
		t.Error("README does not describe the replaced .env and the overlay.env loser")
	}
}
