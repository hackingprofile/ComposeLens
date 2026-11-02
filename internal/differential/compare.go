// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"sort"
	"strings"

	"composelens/internal/containerenv"
	"composelens/internal/engineadapter"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/idpath"
	"composelens/internal/merge"
	"composelens/internal/normalize"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

// CompareInputs compares ComposeLens's effective model to a parsed engine
// config. It does not change either model.
func CompareInputs(internal, engine explain.Input, meta Meta) Report {
	rep := emptyReport(meta)
	if meta.EngineState != "" && meta.EngineState != engineadapter.StateCaptured {
		rep.Certainty = evidence.Unknown
		if meta.EngineState == engineadapter.StateEngineAbsent {
			rep.Evidence = evidence.Absent
		}
		return rep
	}
	compareServices(&rep, internal, engine)
	compareFamilies(&rep, internal, engine)
	compareLeaves(&rep, internal, engine)
	compareEnv(&rep, internal, engine)
	sort.Slice(rep.Rows, func(i, j int) bool {
		if rep.Rows[i].Kind != rep.Rows[j].Kind {
			return kindOrder(rep.Rows[i].Kind) < kindOrder(rep.Rows[j].Kind)
		}
		return rep.Rows[i].Path < rep.Rows[j].Path
	})
	return rep
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

func compareServices(rep *Report, in, eng explain.Input) {
	names := map[string]struct{}{}
	for n := range enabledSet(in) {
		names[n] = struct{}{}
	}
	for n := range enabledSet(eng) {
		names[n] = struct{}{}
	}
	order := sortedKeys(names)
	for _, name := range order {
		lOn := enabledSet(in)[name]
		rOn := enabledSet(eng)[name]
		row := Row{Path: name, Kind: KindService}
		switch {
		case lOn && rOn:
			row.State = StateMatch
			row.Internal = profiles.StateEnabled
			row.Engine = profiles.StateEnabled
		case lOn && !rOn:
			row.State = StateOnlyInternal
			row.Internal = profiles.StateEnabled
			row.Detail = "enabled internally; absent from engine config"
		case !lOn && rOn:
			row.State = StateOnlyEngine
			row.Engine = profiles.StateEnabled
			row.Detail = "present in engine config; not enabled internally"
		default:
			continue
		}
		rep.add(row)
	}
}

func compareFamilies(rep *Report, in, eng explain.Input) {
	known := knownOf(in, eng)
	lm := normalize.FromMerge(in.Merge)
	em := normalize.FromMerge(eng.Merge)
	roots := map[string]struct{}{}
	for _, f := range in.Merge {
		if root, ok := normalize.FamilyRoot(f.Path, known); ok {
			roots[root] = struct{}{}
		}
	}
	for _, f := range eng.Merge {
		if root, ok := normalize.FamilyRoot(f.Path, known); ok {
			roots[root] = struct{}{}
		}
	}
	for _, root := range sortedKeys(roots) {
		svc := serviceOf(root, known)
		lOn := enabledSet(in)[svc]
		rOn := enabledSet(eng)[svc]
		if !lOn && !rOn {
			continue
		}
		ls, _ := normalize.ServiceByName(lm, svc)
		rs, _ := normalize.ServiceByName(em, svc)
		lText, lPresent, lSecret := normalize.FamilyDisplay(ls, root)
		rText, rPresent, rSecret := normalize.FamilyDisplay(rs, root)
		if !lOn {
			lPresent, lText, lSecret = false, "", false
		}
		if !rOn {
			rPresent, rText, rSecret = false, "", false
		}
		row := Row{Path: root, Kind: KindField, Secret: lSecret || rSecret, Internal: lText, Engine: rText}
		if (lPresent && familyUnknown(ls, root)) || (rPresent && familyUnknown(rs, root)) {
			row.State = StateUncertain
			row.Certainty = evidence.Unknown
			row.Detail = "canonical form unknown on at least one side"
			rep.add(row)
			continue
		}
		switch {
		case lPresent && rPresent:
			switch {
			case row.Secret && (!rawComparable(lText) || !rawComparable(rText)):
				row.State = StateUncertain
				row.Certainty = evidence.Unknown
				row.Detail = secretUncertainDetail
			case normalize.FamilyEqual(ls, rs, root):
				row.State = StateMatch
			default:
				row.State = StateDivergent
				annotateFamilyDivergence(&row, ls, rs, root)
			}
		case lPresent && !rPresent:
			row.State = StateOnlyInternal
			row.Engine = ""
		case !lPresent && rPresent:
			row.State = StateOnlyEngine
			row.Internal = ""
		default:
			continue
		}
		rep.add(row)
	}
}

func compareLeaves(rep *Report, in, eng explain.Input) {
	known := knownOf(in, eng)
	roots := map[string]struct{}{}
	for _, f := range in.Merge {
		if root, ok := groupedFieldRoot(f.Path, known); ok && enabledSet(in)[serviceOf(root, known)] {
			roots[root] = struct{}{}
		}
	}
	for _, f := range eng.Merge {
		if root, ok := groupedFieldRoot(f.Path, known); ok && enabledSet(eng)[serviceOf(root, known)] {
			roots[root] = struct{}{}
		}
	}
	for _, root := range sortedKeys(roots) {
		lText, lOK, lSecret, lUnknown := fieldBundle(in.Merge, root, known)
		rText, rOK, rSecret, rUnknown := fieldBundle(eng.Merge, root, known)
		if !enabledSet(in)[serviceOf(root, known)] {
			lOK, lText, lSecret, lUnknown = false, "", false, false
		}
		if !enabledSet(eng)[serviceOf(root, known)] {
			rOK, rText, rSecret, rUnknown = false, "", false, false
		}
		if !lOK && !rOK {
			continue
		}
		row := Row{Path: root, Kind: KindField, Secret: lSecret || rSecret}
		if lOK {
			row.Internal = lText
		}
		if rOK {
			row.Engine = rText
		}
		if (lOK && lUnknown) || (rOK && rUnknown) {
			row.State = StateUncertain
			row.Certainty = evidence.Unknown
			rep.add(row)
			continue
		}
		if strings.HasSuffix(root, ".networks") && lOK && rOK && !row.Secret && networkListAsMap(lText) == rText {
			// networks: [a, b] is the engine's {a: null, b: null}.
			row.State = StateMatch
			rep.add(row)
			continue
		}
		if lOK != rOK && !row.Secret && emptyValue(lText+rText) {
			// An empty value (hostname: "", a reset or empty list) is what the
			// engine expresses by leaving the field out.
			row.State = StateMatch
			rep.add(row)
			continue
		}
		switch {
		case lOK && rOK:
			switch {
			case row.Secret:
				row.State, row.Certainty, row.Detail = secretBothVerdict(lText, rText)
			case lText == rText:
				row.State = StateMatch
			default:
				row.State = StateDivergent
			}
		case lOK && !rOK:
			row.State = StateOnlyInternal
		default:
			row.State = StateOnlyEngine
		}
		annotateDefaultNetworks(&row)
		rep.add(row)
	}
}

func fieldBundle(fields []merge.Field, root string, known []string) (text string, ok bool, secret bool, unknown bool) {
	var parts []string
	for _, f := range fields {
		got, good := groupedFieldRoot(f.Path, known)
		if !good || got != root {
			continue
		}
		ok = true
		if f.Secret {
			secret = true
		}
		if f.Certainty == evidence.Unknown {
			unknown = true
		}
		rel := strings.TrimPrefix(f.Path, root)
		if rel == "" {
			parts = append(parts, f.Value)
		} else {
			parts = append(parts, strings.TrimPrefix(rel, ".")+"="+f.Value)
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; "), ok, secret, unknown
}

func compareEnv(rep *Report, in, eng explain.Input) {
	keys := map[string]struct{}{}
	collectEnv(keys, in)
	collectEnv(keys, eng)
	for _, raw := range sortedKeys(keys) {
		svc, key, _ := strings.Cut(raw, ":")
		lv, lOK := envVar(in, svc, key)
		rv, rOK := envVar(eng, svc, key)
		if !enabledSet(in)[svc] {
			lOK = false
		}
		if !enabledSet(eng)[svc] {
			rOK = false
		}
		if !lOK && !rOK {
			continue
		}
		secret := (lOK && lv.Secret) || (rOK && rv.Secret) || redact.MustRedact(key, "")
		row := Row{Path: raw, Kind: KindEnv, Secret: secret}
		if lOK {
			row.Internal = lv.Value
		}
		if rOK {
			row.Engine = rv.Value
		}
		if secret {
			switch {
			case lOK && rOK:
				row.State, row.Certainty, row.Detail = secretBothVerdict(lv.Value, rv.Value)
				row.Internal = "present"
				row.Engine = "present"
			case lOK && !rOK:
				row.State = StateOnlyInternal
				row.Internal = "present"
				row.Detail = "secret present internally only; values not shown"
			default:
				row.State = StateOnlyEngine
				row.Engine = "present"
				row.Detail = "secret present on engine only; values not shown"
			}
			rep.add(row)
			continue
		}
		switch {
		case lOK && rOK:
			if lv.Value == rv.Value {
				row.State = StateMatch
			} else {
				row.State = StateDivergent
				annotateEnvDivergence(&row, lv.Value, rv.Value)
			}
		case lOK && !rOK:
			row.State = StateOnlyInternal
		default:
			row.State = StateOnlyEngine
		}
		rep.add(row)
	}
}

func groupedFieldRoot(path string, known []string) (string, bool) {
	if path == "" || strings.Contains(path, "[") {
		return "", false
	}
	if normalize.DualFormPath(path, known) {
		return "", false
	}
	svc, rest, ok := idpath.Parse(path, known)
	if !ok || rest == "" {
		return "", false
	}
	rest = strings.TrimPrefix(rest, ".")
	if rest == "" {
		return "", false
	}
	first, _, _ := strings.Cut(rest, ".")
	switch first {
	case "environment", "env_file", "profiles", "extends", "healthcheck":
		return "", false
	default:
		return idpath.Join(svc, first), true
	}
}

func familyUnknown(s normalize.Service, root string) bool {
	switch {
	case strings.HasSuffix(root, ".ports"):
		for _, p := range s.Ports {
			if p.Provenance.Certainty == evidence.Unknown {
				return true
			}
		}
	case strings.HasSuffix(root, ".volumes"):
		for _, v := range s.Volumes {
			if v.Provenance.Certainty == evidence.Unknown {
				return true
			}
		}
	case strings.HasSuffix(root, ".labels"):
		return s.Labels.Provenance.Certainty == evidence.Unknown
	case strings.HasSuffix(root, ".command"):
		return s.Command != nil && s.Command.Provenance.Certainty == evidence.Unknown
	case strings.HasSuffix(root, ".entrypoint"):
		return s.Entrypoint != nil && s.Entrypoint.Provenance.Certainty == evidence.Unknown
	case strings.HasSuffix(root, ".healthcheck.test"):
		return s.Healthcheck != nil && s.Healthcheck.Provenance.Certainty == evidence.Unknown
	}
	return false
}

func enabledSet(in explain.Input) map[string]bool {
	out := map[string]bool{}
	for _, p := range in.Profiles {
		out[p.Name] = p.State == profiles.StateEnabled
	}
	return out
}

func collectEnv(keys map[string]struct{}, in explain.Input) {
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

func envVar(in explain.Input, svc, key string) (containerenv.Variable, bool) {
	for _, se := range in.Container {
		if se.Service != svc {
			continue
		}
		for _, v := range se.Vars {
			if v.Key == key && v.State == containerenv.StateSet {
				return v, true
			}
		}
	}
	return containerenv.Variable{}, false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
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

// emptyValue reports a field bundle that carries no value: an empty string,
// an empty list or an empty mapping.
func emptyValue(text string) bool {
	switch strings.TrimSpace(text) {
	case "", "[]", "{}":
		return true
	}
	return false
}

// networkListAsMap renders a service networks list "[a, b]" the way the
// engine's mapping form {a: null, b: null} is rendered ("a=; b="), so the two
// spellings of the same attachment compare equal.
func networkListAsMap(text string) string {
	t := strings.TrimSpace(text)
	if !strings.HasPrefix(t, "[") || !strings.HasSuffix(t, "]") {
		return text
	}
	var parts []string
	for _, n := range strings.Split(t[1:len(t)-1], ",") {
		if n = strings.TrimSpace(n); n != "" {
			parts = append(parts, n+"=")
		}
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}
