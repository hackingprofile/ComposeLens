// SPDX-License-Identifier: Apache-2.0

package check

import (
	"path/filepath"
	"sort"
	"strings"

	"composelens/internal/containerenv"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/idpath"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

const (
	CHK01 = "CHK01"
	CHK02 = "CHK02"
	CHK03 = "CHK03"
	CHK04 = "CHK04"
	CHK05 = "CHK05"
	// CHK06 reports input that Compose itself rejects.
	CHK06 = "CHK06"

	SevError   = "error"
	SevWarning = "warning"
	SevInfo    = "info"
)

type Finding struct {
	ID         string
	Severity   string
	Target     string
	Kind       string
	Message    string
	Provenance []string
	Secret     bool
	Certainty  string
	Evidence   string
	// File/Line/Column are SARIF physical-location provenance only.
	// They are not copied into human or JSON reports.
	File   string
	Line   int
	Column int
	// Waived is set when a non-expired policy exception matches this rule.
	Waived        bool
	WaiverExpires string
}

type Result struct {
	Findings     []Finding
	Evidence     string
	Certainty    string
	PolicySchema string
	Gate         string
	sourceBase   string
}

func Evaluate(in explain.Input) Result {
	var out []Finding
	out = append(out, chk01SecretInline(in)...)
	out = append(out, chk02RequiredUnset(in)...)
	out = append(out, chk03ProfiledDependencyGap(in)...)
	out = append(out, chk04MissingTarget(in)...)
	out = append(out, chk05EnvShadowing(in)...)
	out = append(out, chk06ComposeRejects(in)...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].ID != out[j].ID {
			return out[i].ID < out[j].ID
		}
		return out[i].Target < out[j].Target
	})
	return Result{Findings: out, Evidence: evidence.Known, Certainty: evidence.Proven, sourceBase: commonDir(collectSourceFiles(in))}
}

func chk01SecretInline(in explain.Input) []Finding {
	on := enabledSet(in)
	seen := map[string]struct{}{}
	var out []Finding
	add := func(target, kind string, prov []string, secret bool, file string, line, col int) {
		if _, ok := seen[target]; ok {
			return
		}
		seen[target] = struct{}{}
		out = append(out, Finding{
			ID:         CHK01,
			Severity:   SevWarning,
			Target:     target,
			Kind:       kind,
			Message:    "secret-keyed or secret-looking value is defined inline in the Compose model; use an external secret source instead",
			Provenance: prov,
			Secret:     secret,
			Certainty:  evidence.Proven,
			Evidence:   evidence.Known,
			File:       file,
			Line:       line,
			Column:     col,
		})
	}
	for _, se := range in.Container {
		if !on[se.Service] {
			continue
		}
		for _, v := range se.Vars {
			if v.State != containerenv.StateSet || !v.Secret {
				continue
			}
			if v.Winner.Kind != containerenv.KindEnvironment {
				continue
			}
			path := idpath.Join(se.Service, "environment."+v.Key)
			if interpolatedFromExternal(in, path, se.Service, v.Key, v.Winner.Path) {
				continue
			}
			prov := []string{"container-environment:environment"}
			if iv, ok := winningInterp(in, path, se.Service, v.Key, v.Winner.Path); ok && iv.State == interp.StateDefaulted {
				prov = append(prov, "interpolation:defaulted")
			}
			file, line, col := sourceLoc(in, path, se.Service, v.Key, v.Winner.Path, v.Winner.Path, v.Winner.Line)
			add(se.Service+":"+v.Key, "env", prov, true, file, line, col)
		}
	}
	for _, f := range in.Merge {
		if !f.Secret || f.Value == "" {
			continue
		}
		svc := serviceOf(f.Path, in)
		if svc != "" && !on[svc] {
			continue
		}
		if envish(f.Path, in) {
			continue
		}
		if interpolatedFromExternal(in, f.Path, svc, lastSeg(f.Path), f.Winner) {
			continue
		}
		prov := []string{"merge:" + f.Winner}
		if iv, ok := winningInterp(in, f.Path, svc, lastSeg(f.Path), f.Winner); ok && iv.State == interp.StateDefaulted {
			prov = append(prov, "interpolation:defaulted")
		}
		file, line, col := sourceLoc(in, f.Path, svc, lastSeg(f.Path), f.Winner, f.Winner, f.Line)
		add(f.Path, "field", prov, true, file, line, col)
	}
	return out
}

func chk02RequiredUnset(in explain.Input) []Finding {
	on := enabledSet(in)
	var out []Finding
	seen := map[string]struct{}{}
	for _, v := range in.Interp {
		if v.State != interp.StateRequiredError {
			continue
		}
		svc := serviceOf(v.Path, in)
		if svc != "" && !on[svc] {
			continue
		}
		if _, ok := seen[v.Path]; ok {
			continue
		}
		seen[v.Path] = struct{}{}
		src := "interpolation"
		if v.Source != nil && v.Source.Key != "" {
			src += " key=" + v.Source.Key
		}
		out = append(out, Finding{
			ID:         CHK02,
			Severity:   SevError,
			Target:     v.Path,
			Kind:       "field",
			Message:    "required interpolation is unset (${VAR:?} / ${VAR?}); ComposeLens does not fabricate a value",
			Provenance: []string{src},
			Secret:     v.Secret,
			Certainty:  evidence.Proven,
			Evidence:   evidence.Known,
			File:       v.Location.File,
			Line:       v.Location.Line,
			Column:     v.Location.Column,
		})
	}
	return out
}

func chk03ProfiledDependencyGap(in explain.Input) []Finding {
	var out []Finding
	for _, p := range in.Profiles {
		if p.ImplicitOf == "" {
			continue
		}
		if p.State == profiles.StateEnabled {
			continue
		}
		file, line, col := dependsOnLoc(in, p.ImplicitOf)
		out = append(out, Finding{
			ID:         CHK03,
			Severity:   SevWarning,
			Target:     p.Name,
			Kind:       "service",
			Message:    "enabled service depends_on a target gated behind an inactive profile; Compose does not document auto-enabling that dependency",
			Provenance: []string{"profiles:depends_on:" + p.ImplicitOf, "profiles:" + p.State},
			Secret:     redact.LooksLikeSecret(p.Name) || redact.LooksLikeSecret(p.ImplicitOf),
			Certainty:  p.Certainty,
			Evidence:   p.Evidence,
			File:       file,
			Line:       line,
			Column:     col,
		})
	}
	return out
}

func chk04MissingTarget(in explain.Input) []Finding {
	var out []Finding
	var walkInclude func(g *include.Graph)
	walkInclude = func(g *include.Graph) {
		if g == nil {
			return
		}
		for i := range g.Refs {
			ref := g.Refs[i]
			if ref.State == include.StateAbsent {
				out = append(out, Finding{
					ID:         CHK04,
					Severity:   SevError,
					Target:     ref.Spec.Path,
					Kind:       "include",
					Message:    "include: target file is absent",
					Provenance: []string{"include:" + g.File},
					Certainty:  evidence.Proven,
					Evidence:   evidence.Absent,
					File:       g.File,
				})
			}
			walkInclude(ref.Nested)
		}
	}
	for _, g := range in.IncludeGraphs {
		walkInclude(g)
	}
	var walkExtends func(ref extends.Ref, file string)
	walkExtends = func(ref extends.Ref, file string) {
		if ref.State == extends.StateAbsent {
			tgt := ref.Service
			if tgt == "" {
				tgt = ref.Name
			}
			out = append(out, Finding{
				ID:         CHK04,
				Severity:   SevError,
				Target:     tgt,
				Kind:       "extends",
				Message:    "extends target file or service is absent",
				Provenance: []string{"extends:" + file + ":" + ref.Name},
				Certainty:  evidence.Proven,
				Evidence:   evidence.Absent,
				File:       file,
			})
		}
		if ref.Nested != nil {
			walkExtends(*ref.Nested, file)
		}
	}
	for _, g := range in.ExtendsGraphs {
		if g == nil {
			continue
		}
		for _, ref := range g.Refs {
			walkExtends(ref, g.File)
		}
	}
	return out
}

func chk05EnvShadowing(in explain.Input) []Finding {
	on := enabledSet(in)
	var out []Finding
	for _, se := range in.Container {
		if !on[se.Service] {
			continue
		}
		for _, v := range se.Vars {
			if v.State != containerenv.StateSet || len(v.Overridden) == 0 {
				continue
			}
			prov := []string{"winner:" + v.Winner.Kind}
			if v.Winner.Path != "" {
				prov[0] += ":" + v.Winner.Path
			}
			for _, c := range v.Overridden {
				line := "loser:" + c.Kind
				if c.Path != "" {
					line += ":" + c.Path
				}
				prov = append(prov, line)
			}
			out = append(out, Finding{
				ID:         CHK05,
				Severity:   SevInfo,
				Target:     se.Service + ":" + v.Key,
				Kind:       "env",
				Message:    "container-environment variable is set by multiple sources; a lower-precedence source was overridden",
				Provenance: prov,
				Secret:     v.Secret,
				Certainty:  v.Certainty,
				Evidence:   v.Evidence,
				File:       v.Winner.Path,
				Line:       v.Winner.Line,
			})
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

func serviceOf(path string, in explain.Input) string {
	return idpath.Service(path, explain.KnownServices(in))
}

func envish(path string, in explain.Input) bool {
	_, rest, ok := idpath.Parse(path, explain.KnownServices(in))
	if !ok {
		return false
	}
	return strings.HasPrefix(rest, ".environment") || strings.HasPrefix(rest, ".env_file")
}

func lastSeg(path string) string {
	if i := strings.LastIndexByte(path, '.'); i >= 0 {
		path = path[i+1:]
	}
	if i := strings.IndexByte(path, '['); i >= 0 {
		path = path[:i]
	}
	return path
}

func sourceLoc(in explain.Input, path, svc, key, winnerFile, fallbackFile string, fallbackLine int) (file string, line, col int) {
	if iv, ok := winningInterp(in, path, svc, key, winnerFile); ok && iv.Location.File != "" {
		return iv.Location.File, iv.Location.Line, iv.Location.Column
	}
	return fallbackFile, fallbackLine, 0
}

func dependsOnLoc(in explain.Input, svc string) (file string, line, col int) {
	if svc == "" {
		return "", 0, 0
	}
	want := idpath.Join(svc, "depends_on")
	for _, f := range in.Merge {
		if f.Path == want || strings.HasPrefix(f.Path, want+".") || strings.HasPrefix(f.Path, want+"[") {
			file, line, col = sourceLoc(in, f.Path, svc, "depends_on", f.Winner, f.Winner, f.Line)
			if file != "" {
				return file, line, col
			}
		}
	}
	return "", 0, 0
}

func collectSourceFiles(in explain.Input) []string {
	var files []string
	add := func(p string) {
		if p != "" {
			files = append(files, p)
		}
	}
	for _, v := range in.Interp {
		add(v.Location.File)
	}
	for _, f := range in.Merge {
		add(f.Winner)
	}
	for _, se := range in.Container {
		for _, v := range se.Vars {
			add(v.Winner.Path)
		}
	}
	for _, g := range in.IncludeGraphs {
		if g != nil {
			add(g.File)
		}
	}
	for _, g := range in.ExtendsGraphs {
		if g != nil {
			add(g.File)
		}
	}
	return files
}

func interpolatedFromExternal(in explain.Input, path, svc, key, winnerFile string) bool {
	iv, ok := winningInterp(in, path, svc, key, winnerFile)
	if !ok {
		return false
	}
	return skipAsExternalInterp(iv)
}

func winningInterp(in explain.Input, path, svc, key, winnerFile string) (interp.Value, bool) {
	var hit interp.Value
	found := false
	for _, v := range in.Interp {
		if !interpPathMatch(v.Path, path, svc, key) {
			continue
		}
		if winnerFile != "" && v.Location.File != "" && !sameComposeFile(v.Location.File, winnerFile) {
			continue
		}
		hit = v
		found = true
	}
	return hit, found
}

func interpPathMatch(got, path, svc, key string) bool {
	if got == path {
		return true
	}
	if svc == "" || key == "" {
		return false
	}
	return got == idpath.Join(svc, "environment."+key)
}

func sameComposeFile(a, b string) bool {
	a, b = filepath.Clean(a), filepath.Clean(b)
	if a == "." || b == "." || a == "" || b == "" {
		return false
	}
	if strings.EqualFold(a, b) {
		return true
	}
	return strings.EqualFold(filepath.Base(a), filepath.Base(b))
}

func skipAsExternalInterp(v interp.Value) bool {
	switch v.State {
	case interp.StateDefaulted, interp.StateEscapedLiteral:
		return false
	}
	switch v.Form {
	case interp.FormBare, interp.FormBrace:
		return true
	case interp.FormDefaultEmpty, interp.FormDefaultUnset:
		return v.State == interp.StateResolved
	case interp.FormAltNonEmpty, interp.FormAltSet:
		return false
	case interp.FormMixed:
		return v.State == interp.StateResolved
	case interp.FormEscape, "":
		return false
	default:
		raw := strings.TrimSpace(v.Raw)
		if strings.HasPrefix(raw, "$$") {
			return false
		}
		return strings.Contains(raw, "$") && v.State == interp.StateResolved
	}
}

func SecretFragments(r Result) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(val string) {
		if val == "" {
			return
		}
		// Messages are fixed templates; only a secret-shaped message is guard
		// material. No test marker.
		if !redact.LooksLikeSecret(val) {
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
	for _, f := range r.Findings {
		// Message may quote a secret-shaped value. Target and Provenance
		// are identities / path labels; a colon+digit service identity
		// false-trips LooksLikeSecret and then Guard fail-closes on the name.
		add(f.Message)
	}
	return out
}

func Fingerprints(r Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.ID+"|"+f.Severity+"|"+f.Target)
	}
	sort.Strings(out)
	return out
}

// composeTopLevel are the top-level keys Compose accepts besides x-
// extensions.
var composeTopLevel = map[string]bool{
	"version": true, "name": true, "include": true, "services": true, "networks": true,
	"volumes": true, "configs": true, "secrets": true, "models": true,
}

// chk06ComposeRejects reports input that `docker compose config` refuses:
// an unknown top-level key (a typo such as "servics"), a non-string name or
// version, an invalid interpolation format, an include: that is not a list,
// and include or extends cycles. ComposeLens still models what it can, but a
// gate must not pass a file the engine will not load.
func chk06ComposeRejects(in explain.Input) []Finding {
	var out []Finding
	seen := map[string]bool{}
	add := func(target, kind, msg, file string, line, col int, secret bool) {
		key := kind + "\x00" + target + "\x00" + file
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, Finding{
			ID:         CHK06,
			Severity:   SevError,
			Target:     target,
			Kind:       kind,
			Message:    msg,
			Provenance: []string{"compose:" + kind},
			Secret:     secret,
			Certainty:  evidence.Proven,
			Evidence:   evidence.Known,
			File:       file,
			Line:       line,
			Column:     col,
		})
	}
	for _, f := range in.Merge {
		top := f.Path
		if i := strings.IndexAny(top, ".["); i >= 0 {
			top = top[:i]
		}
		switch {
		case strings.HasPrefix(top, "x-"):
		case !composeTopLevel[top]:
			add(top, "file", "unknown top-level key; Compose rejects this file (it accepts version, name, include, services, networks, volumes, configs, secrets, models and x- extensions)", f.Winner, f.Line, 0, false)
		case (top == "name" || top == "version") && top != f.Path:
			add(top, "file", top+" must be a string; Compose rejects this file", f.Winner, f.Line, 0, false)
		}
	}
	for _, v := range in.Interp {
		if v.State == interp.StateInvalid {
			add(v.Path, "field", interp.InvalidFormatMessage, v.Location.File, v.Location.Line, v.Location.Column, v.Secret)
		}
	}
	var walkInclude func(g *include.Graph)
	walkInclude = func(g *include.Graph) {
		if g == nil {
			return
		}
		for _, ref := range g.Refs {
			if ref.Spec.NotList {
				add(ref.Spec.Path, "include", "include: must be a list; Compose rejects this file", g.File, 0, 0, false)
			}
			if ref.State == include.StateCycle {
				add(ref.Spec.Path, "include", "include cycle; Compose rejects this file", g.File, 0, 0, false)
			}
			walkInclude(ref.Nested)
		}
	}
	for _, g := range in.IncludeGraphs {
		walkInclude(g)
	}
	var walkExtends func(ref extends.Ref, file string)
	walkExtends = func(ref extends.Ref, file string) {
		if ref.State == extends.StateCycle {
			add(ref.Name, "extends", "extends cycle; Compose rejects this file", file, 0, 0, false)
			return
		}
		if ref.Nested != nil {
			walkExtends(*ref.Nested, file)
		}
	}
	for _, g := range in.ExtendsGraphs {
		if g == nil {
			continue
		}
		for _, ref := range g.Refs {
			walkExtends(ref, g.File)
		}
	}
	return out
}
