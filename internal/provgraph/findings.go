// SPDX-License-Identifier: Apache-2.0

package provgraph

import (
	"path/filepath"
	"strings"

	"composelens/internal/explain"
	"composelens/internal/include"
	"composelens/internal/paths"
)

// KindInclude is an include reference that did not load (absent, cycle,
// depth, remote or unsupported). Loaded includes appear in field chains.
const KindInclude = "include"

// includeNodes adds one node per include reference that did not load, keyed
// by its resolved path (or the path as written when it was not resolved).
func includeNodes(graphs []*include.Graph) []Node {
	var out []Node
	seen := map[string]struct{}{}
	var walk func(g *include.Graph)
	walk = func(g *include.Graph) {
		if g == nil {
			return
		}
		for _, ref := range g.Refs {
			if ref.State != include.StateOK {
				target := ref.Resolved
				if target == "" {
					target = ref.Spec.Path
				}
				if _, dup := seen[target]; target != "" && !dup {
					seen[target] = struct{}{}
					out = append(out, Node{
						Target: target, Kind: KindInclude, State: ref.State, Effective: ref.State,
						FinalStage: explain.StageInclude, Certainty: ref.Certainty, Evidence: ref.Evidence, Reason: ref.Reason,
						Chain: []Link{{
							Order: 1, Role: RoleWinner, Stage: explain.StageInclude, Kind: KindInclude, Source: g.File,
							State: ref.State, Certainty: ref.Certainty, Evidence: ref.Evidence,
						}},
					})
				}
			}
			walk(ref.Nested)
		}
	}
	for _, g := range graphs {
		walk(g)
	}
	return out
}

// FindingNode returns the one graph node a check finding refers to: the
// finding's own target and kind; for an environment field
// (services.<svc>.environment.<KEY>) the env node <svc>:<KEY>; for an include
// finding the include node of its resolved path. ok is false unless exactly
// one node matches.
func FindingNode(g Graph, target, kind, file string) (Node, bool) {
	type cand struct{ target, kind string }
	cands := []cand{{target, kind}}
	if kind == KindField {
		if rest, ok := strings.CutPrefix(target, "services."); ok {
			if i := strings.Index(rest, ".environment."); i > 0 {
				cands = append(cands, cand{rest[:i] + ":" + rest[i+len(".environment."):], KindEnv})
			}
		}
	}
	if kind == KindInclude && file != "" {
		if r, err := paths.Resolve(filepath.Dir(file), target); err == nil {
			cands = append([]cand{{r, KindInclude}}, cands...)
		}
	}
	for _, c := range cands {
		var hit Node
		n := 0
		for _, node := range g.Nodes {
			if node.Target == c.target && node.Kind == c.kind {
				hit = node
				n++
			}
		}
		if n == 1 {
			return hit, true
		}
	}
	return Node{}, false
}
