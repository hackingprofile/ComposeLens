// SPDX-License-Identifier: Apache-2.0

package provgraph

import (
	"path/filepath"
	"sort"
	"strings"

	"composelens/internal/containerenv"
	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/idpath"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

const (
	RoleWinner   = "winner"
	RoleShadowed = "shadowed"

	KindService = explain.KindService
	KindField   = explain.KindField
	KindEnv     = explain.KindEnv
)

type Input struct {
	Model explain.Input
	Env   []envsrc.Binding
}

type Link struct {
	Order     int
	Role      string
	Stage     string
	Kind      string
	Source    string
	State     string
	Secret    bool
	Certainty string
	Evidence  string
}

type Node struct {
	Target     string
	Kind       string
	State      string
	Effective  string
	Secret     bool
	FinalStage string
	Certainty  string
	Evidence   string
	Reason     string
	Chain      []Link
}

type Graph struct {
	Nodes     []Node
	Evidence  string
	Certainty string
}

func Assemble(in Input) Graph {
	var items []graphItem
	seen := map[string]struct{}{}
	add := func(it graphItem) {
		if it.target == "" || it.kind == "" {
			return
		}
		k := it.kind + "\x00" + it.service + "\x00" + it.path + "\x00" + it.key
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		items = append(items, it)
	}
	on := enabledSet(in.Model)
	for _, p := range in.Model.Profiles {
		add(graphItem{kind: KindService, target: p.Name, service: p.Name})
	}
	for _, f := range in.Model.Merge {
		if f.Service != "" && !on[f.Service] {
			continue
		}
		if !keepField(f) {
			continue
		}
		add(graphItem{kind: KindField, target: f.Path, service: f.Service, path: f.Path})
	}
	for _, se := range in.Model.Container {
		if !on[se.Service] {
			continue
		}
		for _, v := range se.Vars {
			add(graphItem{
				kind:    KindEnv,
				target:  se.Service + ":" + v.Key,
				service: se.Service,
				key:     v.Key,
				path:    idpath.Join(se.Service, "environment."+v.Key),
			})
		}
	}
	sort.Slice(items, func(i, j int) bool {
		ki, kj := kindRank(items[i].kind), kindRank(items[j].kind)
		if ki != kj {
			return ki < kj
		}
		if items[i].target != items[j].target {
			return items[i].target < items[j].target
		}
		return items[i].service < items[j].service
	})
	nodes := make([]Node, 0, len(items))
	for _, it := range items {
		acc := explain.AccountResolved(explain.Target{
			Raw:     it.target,
			Kind:    it.kind,
			Service: it.service,
			Path:    it.path,
			Key:     it.key,
		}, in.Model)
		nodes = append(nodes, nodeFrom(acc, in))
	}
	nodes = append(nodes, includeNodes(in.Model.IncludeGraphs)...)
	return Graph{Nodes: nodes, Evidence: evidence.Known, Certainty: evidence.Proven}
}

type graphItem struct {
	kind, target, service, path, key string
}

func Lookup(g Graph, target string) Node {
	var hits []Node
	for _, n := range g.Nodes {
		if n.Target == target {
			hits = append(hits, n)
		}
	}
	if len(hits) == 1 {
		return hits[0]
	}
	if len(hits) == 0 {
		return Node{Target: target, State: explain.StateAbsent, Evidence: evidence.Absent, Certainty: evidence.Proven, Reason: "target not in the provenance graph"}
	}
	return Node{Target: target, State: explain.StateAbsent, Evidence: evidence.Absent, Certainty: evidence.Proven, Reason: "target matches more than one entity"}
}

func LookupKind(g Graph, target, kind string) Node {
	for _, n := range g.Nodes {
		if n.Target == target && n.Kind == kind {
			return n
		}
	}
	return Node{Target: target, Kind: kind, State: explain.StateAbsent, Evidence: evidence.Absent, Certainty: evidence.Proven, Reason: "target not in the provenance graph"}
}

func nodeFrom(acc explain.Result, in Input) Node {
	n := Node{
		Target:     acc.Target.Raw,
		Kind:       acc.Target.Kind,
		State:      acc.State,
		Effective:  acc.Effective,
		Secret:     acc.Secret,
		FinalStage: acc.FinalStage,
		Certainty:  acc.Certainty,
		Evidence:   acc.Evidence,
		Reason:     acc.Reason,
	}
	if acc.State == explain.StateAbsent {
		return n
	}
	n.Chain = shadowChain(acc, in)
	return n
}

func shadowChain(acc explain.Result, in Input) []Link {
	var out []Link
	seenInterp := false
	for _, st := range acc.Stages {
		switch st.Name {
		case explain.StageInterpolation:
			if !seenInterp {
				out = append(out, interpLinks(acc, in)...)
				seenInterp = true
			}
		case explain.StageInclude:
			for i, hop := range st.Chain {
				role := RoleShadowed
				if i == len(st.Chain)-1 {
					role = RoleWinner
				}
				out = append(out, Link{
					Role: role, Stage: st.Name, Kind: "include", Source: hop,
					State: st.State, Certainty: st.Certainty, Evidence: st.Evidence,
				})
			}
		case explain.StageExtends:
			for i := len(st.Contributors) - 1; i >= 0; i-- {
				role := RoleShadowed
				if i == 0 {
					role = RoleWinner
				}
				out = append(out, Link{
					Role: role, Stage: st.Name, Kind: "extends-" + st.Origin, Source: st.Contributors[i],
					State: st.Origin, Certainty: st.Certainty, Evidence: st.Evidence, Secret: st.Secret,
				})
			}
		case explain.StageMerge:
			out = append(out, mergeLosers(in.Model, acc.Target.Path)...)
			out = append(out, Link{
				Role: RoleWinner, Stage: st.Name, Kind: "file", Source: st.Winner,
				State: st.State, Certainty: st.Certainty, Evidence: st.Evidence, Secret: st.Secret,
			})
		case explain.StageProfiles:
			out = append(out, Link{
				Role: RoleWinner, Stage: st.Name, Kind: "profiles", Source: st.State,
				State: st.State, Certainty: st.Certainty, Evidence: st.Evidence, Secret: st.Secret,
			})
		case explain.StageContainerEnv:
			out = append(out, containerLinks(in.Model, acc.Target.Service, acc.Target.Key)...)
		}
	}
	for i := range out {
		out[i].Order = i + 1
	}
	return out
}

func interpLinks(acc explain.Result, in Input) []Link {
	keys := interpKeys(in.Model, acc)
	if len(keys) == 0 {
		return interpFallback(acc)
	}
	var out []Link
	for _, key := range keys {
		winnerStage, winnerPath := "", ""
		for _, v := range in.Model.Interp {
			if v.Source != nil && v.Source.Key == key {
				winnerStage = v.Source.Stage
				winnerPath = v.Source.Path
				break
			}
		}
		binds := bindingsFor(in.Env, key)
		sort.SliceStable(binds, func(i, j int) bool {
			ri, rj := interpRank(binds[i].Stage), interpRank(binds[j].Stage)
			if ri != rj {
				return ri < rj
			}
			return false
		})
		start := len(out)
		winnerIdx := -1
		for _, b := range binds {
			src := b.Stage
			if b.Path != "" {
				src += ":" + b.Path
			}
			cert := b.Certainty
			if cert == "" {
				cert = evidence.Proven
			}
			out = append(out, Link{
				Role: RoleShadowed, Stage: explain.StageInterpolation, Kind: b.Stage, Source: src,
				State: evidence.Known, Secret: b.Secret, Certainty: cert, Evidence: evidence.Known,
			})
			if winnerStage != "" && b.Stage == winnerStage && (winnerPath == "" || sameRef(b.Path, winnerPath)) {
				winnerIdx = len(out) - 1
			}
		}
		switch {
		case winnerIdx >= 0:
			out[winnerIdx].Role = RoleWinner
		case winnerStage != "":
			src := winnerStage + " key=" + key
			if winnerPath != "" {
				src = winnerStage + ":" + winnerPath
			}
			out = append(out, Link{
				Role: RoleWinner, Stage: explain.StageInterpolation, Kind: winnerStage, Source: src,
				State: evidence.Known, Certainty: evidence.Proven, Evidence: evidence.Known,
			})
		case len(out) > start:
			out[len(out)-1].Role = RoleWinner
		}
	}
	if len(out) == 0 {
		return interpFallback(acc)
	}
	return out
}

func interpFallback(acc explain.Result) []Link {
	for _, st := range acc.Stages {
		if st.Name != explain.StageInterpolation {
			continue
		}
		return []Link{{
			Role: RoleWinner, Stage: st.Name, Kind: st.Source, Source: st.Source,
			State: st.State, Certainty: st.Certainty, Evidence: st.Evidence, Secret: st.Secret,
		}}
	}
	return nil
}

func sameRef(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	return filepath.Clean(a) == filepath.Clean(b)
}

func interpKeys(model explain.Input, acc explain.Result) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(k string) {
		if k == "" {
			return
		}
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, k)
	}
	for _, v := range model.Interp {
		if !explain.InterpMatches(v.Path, v.Raw, acc.Target) {
			continue
		}
		if v.Source != nil {
			add(v.Source.Key)
		}
		for _, vr := range v.Variables {
			add(vr.Key)
		}
	}
	return out
}

func bindingsFor(binds []envsrc.Binding, key string) []envsrc.Binding {
	var out []envsrc.Binding
	for _, b := range binds {
		if b.Key == key {
			out = append(out, b)
		}
	}
	return out
}

func interpRank(stage string) int {
	switch stage {
	case evidence.StageProject:
		return 0
	case evidence.StageEnvFile:
		return 1
	case evidence.StageHost:
		return 2
	default:
		return 9
	}
}

func mergeLosers(model explain.Input, path string) []Link {
	if path == "" {
		return nil
	}
	var f merge.Field
	found := false
	for _, mf := range model.Merge {
		if mf.Path == path {
			f = mf
			found = true
			break
		}
	}
	if !found {
		return nil
	}
	out := make([]Link, 0, len(f.Overridden))
	for _, c := range f.Overridden {
		secret := redact.MustRedactAt(f.Path, c.Value)
		out = append(out, Link{
			Role: RoleShadowed, Stage: explain.StageMerge, Kind: "file", Source: c.File,
			State: c.Action, Secret: secret, Certainty: evidence.Proven, Evidence: evidence.Known,
		})
	}
	return out
}

func containerLinks(model explain.Input, svc, key string) []Link {
	var out []Link
	for _, se := range model.Container {
		if se.Service != svc {
			continue
		}
		for _, v := range se.Vars {
			if v.Key != key {
				continue
			}
			for _, c := range v.Overridden {
				src := c.Kind
				if c.Path != "" {
					src += ":" + c.Path
				}
				secret := redact.MustRedact(v.Key, c.Value)
				out = append(out, Link{
					Role: RoleShadowed, Stage: explain.StageContainerEnv, Kind: c.Kind, Source: src,
					State: containerenv.StateSet, Secret: secret || v.Secret, Certainty: v.Certainty, Evidence: v.Evidence,
				})
			}
			src := v.Winner.Kind
			if v.Winner.Path != "" {
				src += ":" + v.Winner.Path
			}
			out = append(out, Link{
				Role: RoleWinner, Stage: explain.StageContainerEnv, Kind: v.Winner.Kind, Source: src,
				State: v.State, Secret: v.Secret, Certainty: v.Certainty, Evidence: v.Evidence,
			})
			return out
		}
	}
	return out
}

func enabledSet(in explain.Input) map[string]bool {
	out := map[string]bool{}
	for _, p := range in.Profiles {
		out[p.Name] = p.State == profiles.StateEnabled
	}
	return out
}

func keepField(f merge.Field) bool {
	rest := fieldRest(f)
	if rest == "" {
		return false
	}
	if strings.HasPrefix(rest, ".environment") || strings.HasPrefix(rest, ".env_file") {
		return false
	}
	if rest == ".profiles" || strings.HasPrefix(rest, ".profiles[") || strings.HasPrefix(rest, ".profiles.") {
		return false
	}
	if rest == ".extends" || strings.HasPrefix(rest, ".extends.") {
		return false
	}
	return true
}

func fieldRest(f merge.Field) string {
	if f.Service != "" {
		prefix := idpath.Join(f.Service, "")
		if f.Path == prefix {
			return ""
		}
		if strings.HasPrefix(f.Path, prefix+".") || strings.HasPrefix(f.Path, prefix+"[") {
			return f.Path[len(prefix):]
		}
		return ""
	}
	_, rest, ok := idpath.Parse(f.Path, nil)
	if !ok {
		return ""
	}
	return rest
}

func kindRank(kind string) int {
	switch kind {
	case KindService:
		return 0
	case KindField:
		return 1
	case KindEnv:
		return 2
	default:
		return 3
	}
}

func SecretFragments(g Graph) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(key, val string) {
		if val == "" {
			return
		}
		// Key-secret values are already guard material through the model
		// collectors (interp/merge/containerenv); the graph adds only
		// secret-shaped effective values. No test marker.
		if !redact.LooksLikeSecret(val) || !redact.MustRedactAt(key, val) {
			return
		}
		for _, frag := range redact.SecretFragments(val) {
			if frag == "" {
				continue
			}
			if _, ok := seen[frag]; ok {
				continue
			}
			seen[frag] = struct{}{}
			out = append(out, frag)
		}
	}
	for _, n := range g.Nodes {
		// Effective holds values. Target, Reason, and chain Source are
		// identities / provenance labels, never secret material. A
		// colon+digit service identity is ≥32 mixed-class characters and
		// would false-trip LooksLikeSecret.
		add(n.Target, n.Effective)
	}
	return out
}
