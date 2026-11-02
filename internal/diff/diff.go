// SPDX-License-Identifier: Apache-2.0

package diff

import (
	"sort"
	"strings"

	"composelens/internal/containerenv"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/idpath"
	"composelens/internal/merge"
	"composelens/internal/normalize"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

const (
	ChangeAdded   = "added"
	ChangeRemoved = "removed"
	ChangeChanged = "changed"

	KindService = "service"
	KindField   = "field"
	KindEnv     = "env"
)

type SideValue struct {
	Present   bool
	Effective string
	Source    string
	State     string
	Secret    bool
}

type Change struct {
	Target string
	Kind   string
	Change string
	Left   SideValue
	Right  SideValue
	Secret bool
}

type Result struct {
	Changes   []Change
	Evidence  string
	Certainty string
}

func Compare(left, right explain.Input) Result {
	known := knownOf(left, right)
	var out []Change
	out = append(out, serviceChanges(left, right)...)
	out = append(out, fieldChanges(left, right, known)...)
	out = append(out, envChanges(left, right)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return kindOrder(out[i].Kind) < kindOrder(out[j].Kind)
		}
		return out[i].Target < out[j].Target
	})
	return Result{Changes: out, Evidence: evidence.Known, Certainty: evidence.Proven}
}

func kindOrder(k string) int {
	switch k {
	case KindService:
		return 0
	case KindField:
		return 1
	default:
		return 2
	}
}

func serviceChanges(left, right explain.Input) []Change {
	names := map[string]struct{}{}
	for _, p := range left.Profiles {
		names[p.Name] = struct{}{}
	}
	for _, p := range right.Profiles {
		names[p.Name] = struct{}{}
	}
	order := make([]string, 0, len(names))
	for n := range names {
		order = append(order, n)
	}
	sort.Strings(order)
	var out []Change
	for _, name := range order {
		lOn, l := serviceSide(left, name)
		rOn, r := serviceSide(right, name)
		if lOn == rOn {
			continue
		}
		ch := Change{Target: name, Kind: KindService, Left: l, Right: r, Secret: l.Secret || r.Secret}
		if !lOn && rOn {
			ch.Change = ChangeAdded
		} else {
			ch.Change = ChangeRemoved
		}
		out = append(out, ch)
	}
	return out
}

func serviceSide(in explain.Input, name string) (bool, SideValue) {
	for _, p := range in.Profiles {
		if p.Name != name {
			continue
		}
		on := p.State == profiles.StateEnabled
		return on, SideValue{
			Present:   on,
			Effective: p.State,
			Source:    "profiles",
			State:     p.State,
			Secret:    redact.LooksLikeSecret(p.Reason) || redact.LooksLikeSecret(p.Matched) || redact.LooksLikeSecret(name),
		}
	}
	return false, SideValue{}
}

func fieldChanges(left, right explain.Input, known []string) []Change {
	out := canonicalFieldChanges(left, right, known)
	paths := map[string]struct{}{}
	for _, f := range left.Merge {
		if keepMergePath(f.Path, known) && !normalize.DualFormPath(f.Path, known) {
			paths[f.Path] = struct{}{}
		}
	}
	for _, f := range right.Merge {
		if keepMergePath(f.Path, known) && !normalize.DualFormPath(f.Path, known) {
			paths[f.Path] = struct{}{}
		}
	}
	order := make([]string, 0, len(paths))
	for p := range paths {
		order = append(order, p)
	}
	sort.Strings(order)
	for _, path := range order {
		l := fieldSide(left, path, known)
		r := fieldSide(right, path, known)
		if !l.Present && !r.Present {
			continue
		}
		if l.Present && r.Present && l.Effective == r.Effective && l.Source == r.Source {
			continue
		}
		ch := Change{Target: path, Kind: KindField, Left: l, Right: r, Secret: l.Secret || r.Secret}
		switch {
		case !l.Present && r.Present:
			ch.Change = ChangeAdded
		case l.Present && !r.Present:
			ch.Change = ChangeRemoved
		default:
			ch.Change = ChangeChanged
		}
		out = append(out, ch)
	}
	return out
}

func canonicalFieldChanges(left, right explain.Input, known []string) []Change {
	lm := normalize.FromMerge(left.Merge)
	rm := normalize.FromMerge(right.Merge)
	roots := map[string]struct{}{}
	addRoots := func(fields []merge.Field) {
		for _, f := range fields {
			if root, ok := normalize.FamilyRoot(f.Path, known); ok {
				roots[root] = struct{}{}
			}
		}
	}
	addRoots(left.Merge)
	addRoots(right.Merge)
	order := make([]string, 0, len(roots))
	for r := range roots {
		order = append(order, r)
	}
	sort.Strings(order)
	var out []Change
	for _, root := range order {
		svc := serviceOf(root, known)
		lOn, _ := serviceSide(left, svc)
		rOn, _ := serviceSide(right, svc)
		if !lOn && !rOn {
			continue
		}
		ls, _ := normalize.ServiceByName(lm, svc)
		rs, _ := normalize.ServiceByName(rm, svc)
		lText, lPresent, lSecret := normalize.FamilyDisplay(ls, root)
		rText, rPresent, rSecret := normalize.FamilyDisplay(rs, root)
		if !lOn {
			lPresent, lText, lSecret = false, "", false
		}
		if !rOn {
			rPresent, rText, rSecret = false, "", false
		}
		if lPresent && rPresent && lOn && rOn && normalize.FamilyEqual(ls, rs, root) {
			continue
		}
		if !lPresent && !rPresent {
			continue
		}
		ch := Change{
			Target: root,
			Kind:   KindField,
			Left: SideValue{
				Present:   lPresent,
				Effective: lText,
				Source:    canonicalSource(left, root, ls),
				Secret:    lSecret,
			},
			Right: SideValue{
				Present:   rPresent,
				Effective: rText,
				Source:    canonicalSource(right, root, rs),
				Secret:    rSecret,
			},
			Secret: lSecret || rSecret,
		}
		switch {
		case !lPresent && rPresent:
			ch.Change = ChangeAdded
		case lPresent && !rPresent:
			ch.Change = ChangeRemoved
		default:
			ch.Change = ChangeChanged
		}
		out = append(out, ch)
	}
	return out
}

func canonicalSource(in explain.Input, root string, svc normalize.Service) string {
	acc := explain.Account(root, in)
	if acc.FinalStage != "" {
		return winningSource(acc)
	}
	return normalize.FamilySource(svc, root)
}

func fieldSide(in explain.Input, path string, known []string) SideValue {
	svc := serviceOf(path, known)
	if svc != "" {
		on, _ := serviceSide(in, svc)
		if !on {
			return SideValue{}
		}
	}
	mf, ok := mergeField(in.Merge, path)
	if !ok {
		return SideValue{}
	}
	acc := explain.Account(path, in)
	return SideValue{
		Present:   true,
		Effective: mf.Value,
		Source:    winningSource(acc),
		Secret:    mf.Secret || acc.Secret,
	}
}

func envChanges(left, right explain.Input) []Change {
	keys := map[string]struct{}{}
	collectEnvKeys(keys, left)
	collectEnvKeys(keys, right)
	order := make([]string, 0, len(keys))
	for k := range keys {
		order = append(order, k)
	}
	sort.Strings(order)
	var out []Change
	for _, raw := range order {
		l := envSide(left, raw)
		r := envSide(right, raw)
		if !l.Present && !r.Present {
			continue
		}
		if l.Present && r.Present && l.Effective == r.Effective && l.Source == r.Source {
			continue
		}
		ch := Change{Target: raw, Kind: KindEnv, Left: l, Right: r, Secret: l.Secret || r.Secret}
		switch {
		case !l.Present && r.Present:
			ch.Change = ChangeAdded
		case l.Present && !r.Present:
			ch.Change = ChangeRemoved
		default:
			ch.Change = ChangeChanged
		}
		out = append(out, ch)
	}
	return out
}

func collectEnvKeys(keys map[string]struct{}, in explain.Input) {
	on := enabledSet(in)
	for _, se := range in.Container {
		if !on[se.Service] {
			continue
		}
		for _, v := range se.Vars {
			if v.State != containerenv.StateSet {
				continue
			}
			keys[se.Service+":"+v.Key] = struct{}{}
		}
	}
}

func envSide(in explain.Input, raw string) SideValue {
	tgt, ok := explain.ParseTarget(raw, explain.KnownServices(in))
	if !ok || tgt.Kind != explain.KindEnv {
		return SideValue{}
	}
	on, _ := serviceSide(in, tgt.Service)
	if !on {
		return SideValue{}
	}
	acc := explain.Account(raw, in)
	if acc.State == explain.StateAbsent {
		return SideValue{}
	}
	for _, se := range in.Container {
		if se.Service != tgt.Service {
			continue
		}
		for _, v := range se.Vars {
			if v.Key != tgt.Key {
				continue
			}
			if v.State != containerenv.StateSet {
				return SideValue{}
			}
			return SideValue{
				Present:   true,
				Effective: v.Value,
				Source:    winningSource(acc),
				Secret:    v.Secret || acc.Secret,
				State:     v.State,
			}
		}
	}
	return SideValue{}
}

func enabledSet(in explain.Input) map[string]bool {
	out := map[string]bool{}
	for _, p := range in.Profiles {
		out[p.Name] = p.State == profiles.StateEnabled
	}
	return out
}

func keepMergePath(path string, known []string) bool {
	svc, rest, ok := idpath.Parse(path, known)
	if !ok {
		return path != ""
	}
	_ = svc
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

func serviceOf(path string, known []string) string {
	return idpath.Service(path, known)
}

func knownOf(ins ...explain.Input) []string {
	var all []string
	for _, in := range ins {
		all = append(all, explain.KnownServices(in)...)
	}
	return idpath.Unique(all)
}

func mergeField(fields []merge.Field, path string) (merge.Field, bool) {
	for _, f := range fields {
		if f.Path == path {
			return f, true
		}
	}
	return merge.Field{}, false
}

func winningSource(r explain.Result) string {
	if r.FinalStage == "" {
		return ""
	}
	for i := len(r.Stages) - 1; i >= 0; i-- {
		st := r.Stages[i]
		if st.Name != r.FinalStage {
			continue
		}
		parts := []string{st.Name}
		if st.Winner != "" {
			parts = append(parts, st.Winner)
		}
		if st.Source != "" && st.Source != st.Winner {
			parts = append(parts, st.Source)
		}
		if st.Origin != "" && st.Origin != st.Winner && st.Origin != st.Source {
			parts = append(parts, st.Origin)
		}
		return strings.Join(parts, ":")
	}
	return r.FinalStage
}

func SecretFragments(r Result) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(key, val string) {
		if val == "" {
			return
		}
		if !redact.MustRedact(key, val) && !redact.LooksLikeSecret(val) {
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
		if !redact.LooksLikeSecret(val) {
			if _, ok := seen[val]; !ok {
				seen[val] = struct{}{}
				out = append(out, val)
			}
		}
	}
	for _, c := range r.Changes {
		key := c.Target
		if i := strings.LastIndexByte(c.Target, ':'); i > 0 && c.Kind == KindEnv {
			key = c.Target[i+1:]
		}
		add(key, c.Left.Effective)
		add(key, c.Right.Effective)
		// Source is a provenance label (stage:file), not a secret value.
	}
	return out
}
