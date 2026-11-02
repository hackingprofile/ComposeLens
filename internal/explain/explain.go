// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"strings"

	"composelens/internal/containerenv"
	"composelens/internal/evidence"
	"composelens/internal/extends"
	"composelens/internal/idpath"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

const (
	KindService = "service"
	KindField   = "field"
	KindEnv     = "env"

	StateOK     = "ok"
	StateAbsent = "absent"

	StageInterpolation = "interpolation"
	StageInclude       = "include"
	StageExtends       = "extends"
	StageMerge         = "merge"
	StageProfiles      = "profiles"
	StageContainerEnv  = "container-environment"
)

type Target struct {
	Raw     string
	Kind    string
	Service string
	Path    string
	Key     string
}

type Input struct {
	Interp        []interp.Value
	Merge         []merge.Field
	Chains        map[string][]string
	Extends       map[string]extends.Field
	Profiles      []profiles.Service
	Container     []containerenv.ServiceEnv
	IncludeGraphs []*include.Graph
	ExtendsGraphs []*extends.Graph
}

type Stage struct {
	Name         string
	Summary      string
	Path         string
	Value        string
	Raw          string
	State        string
	Source       string
	Winner       string
	Origin       string
	Chain        []string
	Contributors []string
	Overridden   []string
	// OverriddenValues holds the raw loser value that ends each Overridden
	// line, in the same order, so the view layer can withhold the value while
	// keeping the source label.
	OverriddenValues []string
	// Line and Column locate the winning source (0 when unknown).
	Line      int
	Column    int
	Secret    bool
	Certainty string
	Evidence  string
	Reason    string
}

type Result struct {
	Target     Target
	State      string
	Reason     string
	Stages     []Stage
	Effective  string
	Secret     bool
	Certainty  string
	Evidence   string
	FinalStage string
}

func ParseTarget(raw string, known []string) (Target, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, false
	}
	if tgt, ok := envTarget(raw); ok {
		return tgt, true
	}
	if strings.HasPrefix(raw, "services.") {
		svc, extra, ok := idpath.Parse(raw, known)
		if !ok || svc == "" {
			return Target{}, false
		}
		if extra == "" {
			return Target{Raw: raw, Kind: KindService, Service: svc}, true
		}
		return Target{Raw: raw, Kind: KindField, Service: svc, Path: raw}, true
	}
	return Target{Raw: raw, Kind: KindService, Service: raw}, true
}

func envTarget(raw string) (Target, bool) {
	i := strings.IndexByte(raw, ':')
	if i <= 0 {
		return Target{}, false
	}
	svc := raw[:i]
	key := raw[i+1:]
	if svc == "" || !idpath.EnvOK(key) {
		return Target{}, false
	}
	return Target{Raw: raw, Kind: KindEnv, Service: svc, Key: key, Path: idpath.Join(svc, "environment."+key)}, true
}

func fieldOwners(in Input, path string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range in.Merge {
		if f.Path != path || f.Service == "" {
			continue
		}
		if _, ok := seen[f.Service]; ok {
			continue
		}
		seen[f.Service] = struct{}{}
		out = append(out, f.Service)
	}
	return out
}

func namedService(in Input, raw string) bool {
	for _, n := range KnownServices(in) {
		if n == raw {
			return true
		}
	}
	return false
}

// ResolveTarget maps a textual target using known service names and merge
// field owners so a service named like a path is not reparsed as another
// service's field. Ambiguous strings return ok=false.
func ResolveTarget(raw string, in Input) (Target, bool, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return Target{}, false, "explain target is empty or not a service, field path, or service:VAR"
	}
	if tgt, ok := envTarget(raw); ok {
		return tgt, true, ""
	}
	named := namedService(in, raw)
	owners := fieldOwners(in, raw)
	if named && len(owners) > 0 {
		same := len(owners) == 1 && owners[0] == raw
		root := len(owners) == 1 && raw == idpath.Join(owners[0], "")
		if !same && !root {
			return Target{Raw: raw}, false, "target matches more than one entity"
		}
	}
	if named {
		return Target{Raw: raw, Kind: KindService, Service: raw}, true, ""
	}
	if len(owners) == 1 {
		owner := owners[0]
		if raw == idpath.Join(owner, "") {
			return Target{Raw: raw, Kind: KindService, Service: owner}, true, ""
		}
		return Target{Raw: raw, Kind: KindField, Service: owner, Path: raw}, true, ""
	}
	if len(owners) > 1 {
		return Target{Raw: raw}, false, "target matches more than one entity"
	}
	tgt, ok := ParseTarget(raw, KnownServices(in))
	if !ok {
		return Target{Raw: raw}, false, "explain target is empty or not a service, field path, or service:VAR"
	}
	return tgt, true, ""
}

func KnownServices(in Input) []string {
	var explicit []string
	for _, p := range in.Profiles {
		explicit = append(explicit, p.Name)
	}
	var paths []string
	for _, f := range in.Merge {
		explicit = append(explicit, f.Service)
		paths = append(paths, f.Path)
	}
	for _, se := range in.Container {
		explicit = append(explicit, se.Service)
	}
	return idpath.Collect(explicit, paths)
}

func Account(raw string, in Input) Result {
	tgt, ok, reason := ResolveTarget(raw, in)
	if !ok {
		if reason == "" {
			reason = "explain target is empty or not a service, field path, or service:VAR"
		}
		return Result{Target: tgt, State: StateAbsent, Reason: reason, Evidence: evidence.Absent, Certainty: evidence.Proven}
	}
	return AccountResolved(tgt, in)
}

// AccountResolved composes an account for an already-identified entity.
// Graph assembly uses this so a known service or field is not reparsed as a
// colliding textual target.
func AccountResolved(tgt Target, in Input) Result {
	if tgt.Raw == "" {
		return Result{Target: tgt, State: StateAbsent, Reason: "explain target is empty or not a service, field path, or service:VAR", Evidence: evidence.Absent, Certainty: evidence.Proven}
	}
	r := Result{Target: tgt, State: StateOK, Evidence: evidence.Known, Certainty: evidence.Proven}
	svcOK := serviceKnown(in, tgt.Service)
	switch tgt.Kind {
	case KindService:
		if !svcOK {
			return absent(tgt, "service not found")
		}
		if st, ok := profileStage(in, tgt.Service); ok {
			r.Stages = append(r.Stages, st)
			r.Effective = st.State
			r.FinalStage = StageProfiles
			r.Secret = st.Secret
			carryUncertainty(&r, st)
		}
	case KindField:
		mf, found := mergeField(in.Merge, tgt.Path)
		if !found {
			return absent(tgt, "field not found")
		}
		r.Stages = appendFieldStages(r.Stages, in, tgt, mf)
		r.Effective = mf.Value
		r.Secret = mf.Secret
		r.FinalStage = StageMerge
		if st, ok := profileStage(in, tgt.Service); ok {
			r.Stages = append(r.Stages, st)
			carryUncertainty(&r, st)
		}
	case KindEnv:
		if !svcOK {
			return absent(tgt, "service not found")
		}
		cv, found := containerVar(in.Container, tgt.Service, tgt.Key)
		if !found {
			return absent(tgt, "container environment variable not found")
		}
		envPath := envMergePath(in.Merge, tgt.Service, tgt.Key)
		if envPath != "" {
			if mf, ok := mergeField(in.Merge, envPath); ok {
				r.Stages = appendFieldStages(r.Stages, in, Target{Kind: KindField, Service: tgt.Service, Path: envPath}, mf)
			}
		} else {
			r.Stages = appendInterpStages(r.Stages, in, tgt)
		}
		if p, ok := profileStage(in, tgt.Service); ok {
			r.Stages = append(r.Stages, p)
			carryUncertainty(&r, p)
		}
		st := containerStage(cv)
		r.Stages = append(r.Stages, st)
		r.Effective = cv.Value
		r.Secret = cv.Secret || st.Secret
		r.FinalStage = StageContainerEnv
		if cv.State == containerenv.StateUnset {
			r.Effective = ""
			r.Reason = "variable unset in container environment"
		}
		carryUncertainty(&r, st)
	}
	for i := range r.Stages {
		if r.Stages[i].Secret {
			r.Secret = true
		}
		carryUncertainty(&r, r.Stages[i])
	}
	if r.Secret {
		r.Secret = true
	}
	return r
}

func appendFieldStages(stages []Stage, in Input, tgt Target, mf merge.Field) []Stage {
	stages = appendInterpStages(stages, in, tgt)
	if ch := in.Chains[mf.Winner]; len(ch) > 1 {
		stages = append(stages, Stage{
			Name:      StageInclude,
			Summary:   "include chain of the winning file",
			Winner:    mf.Winner,
			Chain:     append([]string{}, ch...),
			Certainty: evidence.Proven,
			Evidence:  evidence.Known,
		})
	}
	if ex, ok := in.Extends[tgt.Path]; ok && (ex.BaseService != "" || ex.Origin == extends.OriginInherited || ex.Origin == extends.OriginOverride || ex.Origin == extends.OriginConcat) {
		st := Stage{
			Name:         StageExtends,
			Summary:      "extends origin from the resolved service",
			Path:         tgt.Path,
			Origin:       ex.Origin,
			Winner:       ex.BaseService,
			Chain:        append([]string{}, ex.Chain...),
			Contributors: append([]string{}, ex.Sources...),
			Value:        ex.Value,
			Secret:       ex.Secret,
			Certainty:    ex.Certainty,
			Evidence:     ex.Evidence,
			Reason:       "base=" + ex.BaseService,
		}
		if ex.BaseFile != "" {
			st.Source = ex.BaseFile
		}
		stages = append(stages, st)
	}
	ov := make([]string, 0, len(mf.Overridden))
	ovVals := make([]string, 0, len(mf.Overridden))
	secret := mf.Secret
	for _, c := range mf.Overridden {
		ov = append(ov, c.File+" "+c.Action+" "+c.Value)
		ovVals = append(ovVals, c.Value)
		if redact.MustRedactAt(mf.Path, c.Value) {
			secret = true
		}
	}
	stages = append(stages, Stage{
		Name:             StageMerge,
		Summary:          "multi-file merge winner",
		Path:             mf.Path,
		Value:            mf.Value,
		State:            mf.Action,
		Winner:           mf.Winner,
		Overridden:       ov,
		OverriddenValues: ovVals,
		Line:             mf.Line,
		Column:           mf.Column,
		Secret:           secret,
		Certainty:        mf.Certainty,
		Evidence:         mf.Evidence,
	})
	return stages
}

func appendInterpStages(stages []Stage, in Input, tgt Target) []Stage {
	for _, v := range in.Interp {
		if !interpMatches(v.Path, v.Raw, tgt) {
			continue
		}
		src := ""
		if v.Source != nil {
			src = v.Source.Stage
			if v.Source.Key != "" {
				src += " key=" + v.Source.Key
			}
		}
		stages = append(stages, Stage{
			Name:      StageInterpolation,
			Summary:   "Compose-file interpolation (not container environment)",
			Path:      v.Path,
			Raw:       v.Raw,
			Value:     v.Resolved,
			State:     v.State,
			Source:    src,
			Secret:    v.Secret,
			Certainty: v.Certainty,
			Evidence:  v.Evidence,
			Reason:    v.Error,
		})
	}
	return stages
}

// InterpMatches reports whether an interpolation item applies to a target.
// Shared with the provenance graph so env-nodes and field-nodes use the same lookup.
func InterpMatches(path, raw string, tgt Target) bool {
	return interpMatches(path, raw, tgt)
}

func interpMatches(path, raw string, tgt Target) bool {
	switch tgt.Kind {
	case KindField:
		return path == tgt.Path
	case KindEnv:
		if path == tgt.Path || path == "services."+tgt.Service+".environment."+tgt.Key {
			return true
		}
		prefix := "services." + tgt.Service + ".environment["
		if strings.HasPrefix(path, prefix) && !strings.Contains(path[len(prefix):], ".") {
			return raw == tgt.Key || strings.HasPrefix(raw, tgt.Key+"=")
		}
		return false
	default:
		return false
	}
}

func mergeField(fields []merge.Field, path string) (merge.Field, bool) {
	for _, f := range fields {
		if f.Path == path {
			return f, true
		}
	}
	return merge.Field{}, false
}

func envMergePath(fields []merge.Field, svc, key string) string {
	want := "services." + svc + ".environment." + key
	if _, ok := mergeField(fields, want); ok {
		return want
	}
	prefix := "services." + svc + ".environment["
	for _, f := range fields {
		if !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		if strings.Contains(f.Path[len(prefix):], ".") {
			continue
		}
		if f.Value == key || strings.HasPrefix(f.Value, key+"=") {
			return f.Path
		}
	}
	return ""
}

func containerVar(svcs []containerenv.ServiceEnv, svc, key string) (containerenv.Variable, bool) {
	for _, s := range svcs {
		if s.Service != svc {
			continue
		}
		for _, v := range s.Vars {
			if v.Key == key {
				return v, true
			}
		}
	}
	return containerenv.Variable{}, false
}

func containerStage(v containerenv.Variable) Stage {
	ov := make([]string, 0, len(v.Overridden))
	ovVals := make([]string, 0, len(v.Overridden))
	secret := v.Secret
	for _, c := range v.Overridden {
		ov = append(ov, c.Kind+" "+c.Path+" "+c.Value)
		ovVals = append(ovVals, c.Value)
		if redact.MustRedact(v.Key, c.Value) {
			secret = true
		}
	}
	return Stage{
		Name:             StageContainerEnv,
		Summary:          "container environment winner (not interpolation)",
		Path:             v.Key,
		Value:            v.Value,
		State:            v.State,
		Winner:           v.Winner.Kind,
		Source:           v.Winner.Path,
		Origin:           v.Winner.Form,
		Line:             v.Winner.Line,
		Overridden:       ov,
		OverriddenValues: ovVals,
		Secret:           secret,
		Certainty:        v.Certainty,
		Evidence:         v.Evidence,
		Reason:           v.Reason,
	}
}

func profileStage(in Input, svc string) (Stage, bool) {
	for _, p := range in.Profiles {
		if p.Name != svc {
			continue
		}
		return Stage{
			Name:      StageProfiles,
			Summary:   "profile activation of the service",
			State:     p.State,
			Reason:    p.Reason,
			Certainty: p.Certainty,
			Evidence:  p.Evidence,
			Secret:    redact.LooksLikeSecret(p.Reason) || redact.LooksLikeSecret(p.Matched),
		}, true
	}
	return Stage{}, false
}

func serviceKnown(in Input, name string) bool {
	for _, n := range KnownServices(in) {
		if n == name {
			return true
		}
	}
	return false
}

func absent(tgt Target, reason string) Result {
	return Result{
		Target:    tgt,
		State:     StateAbsent,
		Reason:    reason,
		Stages:    nil,
		Evidence:  evidence.Absent,
		Certainty: evidence.Proven,
	}
}

func carryUncertainty(r *Result, st Stage) {
	if st.Evidence == evidence.Unsupported || st.Certainty == evidence.Unknown {
		if r.Evidence != evidence.Absent {
			r.Evidence = st.Evidence
			r.Certainty = st.Certainty
		}
	}
}

func SecretFragments(r Result) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(key, val string) {
		if val == "" {
			return
		}
		if redact.MustRedactAt(key, val) {
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
	}
	add(r.Target.Key, r.Effective)
	for _, st := range r.Stages {
		add(st.Path, st.Value)
		add(st.Path, st.Raw)
		for _, o := range st.Overridden {
			add("", o)
		}
		// Losers are classified under the same key as the winner so a
		// key-secret loser (plain value under PASSWORD) is guard material too.
		for _, v := range st.OverriddenValues {
			add(st.Path, v)
		}
	}
	return out
}
