// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"composelens/internal/check"
	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/envsrc"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/normalize"
	"composelens/internal/paths"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

type envGet map[string]string

func (e envGet) Get(key string) (value string, present bool, src interp.Source) {
	v, ok := e[key]
	return v, ok, interp.Source{Key: key, Stage: "fixture-catalog"}
}

func Run(fixturesRoot string) (Report, error) {
	rep := emptyReport()
	cat, err := LoadCatalog(filepath.Join(fixturesRoot, "catalog.yaml"))
	if err != nil {
		return rep, err
	}
	undeclared, err := Undeclared(fixturesRoot, cat)
	if err != nil {
		return rep, err
	}
	sort.Strings(undeclared)
	if undeclared == nil {
		undeclared = []string{}
	}
	rep.Undeclared = undeclared
	if len(undeclared) > 0 {
		return rep, fmt.Errorf("undeclared fixture files: %s", strings.Join(undeclared, ", "))
	}
	for _, fx := range cat.Fixtures {
		res := evalFixture(fixturesRoot, fx)
		rep.Results = append(rep.Results, res)
		rep.Total++
		switch res.Status {
		case StatusPassed:
			rep.Passed++
		case StatusFailed:
			rep.Failed++
		case StatusSkipped:
			rep.Skipped++
		}
		if res.PendingEngine {
			rep.PendingEngine++
		}
		fc := rep.ByFeature[fx.Feature]
		kc := rep.ByKind[fx.Kind]
		bump := func(c *Counts) {
			c.Total++
			switch res.Status {
			case StatusPassed:
				c.Passed++
			case StatusFailed:
				c.Failed++
			case StatusSkipped:
				c.Skipped++
			}
			if res.PendingEngine {
				c.PendingEngine++
			}
		}
		bump(&fc)
		bump(&kc)
		rep.ByFeature[fx.Feature] = fc
		rep.ByKind[fx.Kind] = kc
	}
	if err := scanSecrets(fixturesRoot, cat); err != nil {
		return rep, err
	}
	return rep, nil
}

func evalFixture(root string, fx Fixture) Result {
	res := Result{
		ID:            fx.ID,
		Feature:       fx.Feature,
		Kind:          fx.Kind,
		PendingEngine: fx.Expected.Engine == EnginePending,
		Status:        StatusPassed,
	}
	if err := filesExist(root, fx.Files); err != nil {
		res.Status = StatusFailed
		res.Detail = err.Error()
		return res
	}
	if err := runAssertion(root, fx); err != nil {
		if errors.Is(err, errSkipped) {
			res.Status = StatusSkipped
			res.Detail = "platform fixture skipped on this GOOS"
			return res
		}
		res.Status = StatusFailed
		res.Detail = err.Error()
		return res
	}
	return res
}

var errSkipped = errors.New("skipped")

func filesExist(root string, files []string) error {
	for _, f := range files {
		p := filepath.Join(root, filepath.FromSlash(f))
		if _, err := os.Stat(p); err != nil {
			return fmt.Errorf("missing %s: %w", f, err)
		}
	}
	return nil
}

func runAssertion(root string, fx Fixture) error {
	loc := fx.Expected.Local
	switch loc.Assertion {
	case "parse-services":
		return assertParseServices(root, fx)
	case "parse-ok":
		return assertParseOK(root, fx)
	case "path-cases":
		return assertPathCases(root, fx)
	case "merge-path-equals":
		return assertMergePaths(root, fx)
	case "interp-path-states":
		return assertInterp(root, fx)
	case "profiles-states":
		return assertProfiles(root, fx)
	case "include-merge-path":
		return assertIncludeMerge(root, fx)
	case "include-ref":
		return assertIncludeRef(root, fx)
	case "extends-field":
		return assertExtendsField(root, fx)
	case "extends-ref":
		return assertExtendsRef(root, fx)
	case "containerenv-var":
		return assertContainerEnv(root, fx)
	case "check-ids":
		return assertCheckIDs(root, fx)
	case "normalize-equal":
		return assertNormalize(root, fx, true)
	case "normalize-unequal":
		return assertNormalize(root, fx, false)
	case "normalize-unknown":
		return assertNormalizeUnknown(root, fx)
	case "files-exist":
		return nil
	default:
		return fmt.Errorf("unknown local assertion %q", loc.Assertion)
	}
}

func parseFile(root, rel string) (*composeparse.Document, error) {
	p := filepath.Join(root, filepath.FromSlash(rel))
	raw, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return nil, err
	}
	return composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
}

func assertParseServices(root string, fx Fixture) error {
	doc, err := parseFile(root, fx.Files[0])
	if err != nil {
		return err
	}
	got := map[string]struct{}{}
	for _, s := range doc.Services {
		got[s.Name] = struct{}{}
	}
	for _, name := range fx.Expected.Local.Services {
		if _, ok := got[name]; !ok {
			return fmt.Errorf("missing service %s", name)
		}
	}
	if len(fx.Expected.Local.Services) > 0 && len(doc.Services) != len(fx.Expected.Local.Services) {
		return fmt.Errorf("service count %d want %d", len(doc.Services), len(fx.Expected.Local.Services))
	}
	return nil
}

func assertParseOK(root string, fx Fixture) error {
	entry := fx.Files[0]
	if fx.Entry != "" {
		entry = fx.Entry
	}
	_, err := parseFile(root, entry)
	return err
}

func goosMatches(want string) bool {
	if want == "" {
		return true
	}
	have := currentGOOS()
	if want == have {
		return true
	}
	if want == "posix" {
		return have != "windows"
	}
	return false
}

func assertPathCases(root string, fx Fixture) error {
	if !goosMatches(fx.Expected.Local.GOOS) {
		return errSkipped
	}
	p := filepath.Join(root, filepath.FromSlash(fx.Files[0]))
	raw, err := os.ReadFile(p)
	if err != nil {
		return err
	}
	var fxFile struct {
		GOOS  string `json:"goos"`
		Cases []struct {
			Name       string `json:"name"`
			ProjectDir string `json:"projectDir"`
			Relative   string `json:"relative"`
			WantSlash  string `json:"wantSlash"`
		} `json:"cases"`
	}
	if err := jsonUnmarshal(raw, &fxFile); err != nil {
		return err
	}
	if fxFile.GOOS != "" && !goosMatches(fxFile.GOOS) {
		return errSkipped
	}
	for _, c := range fxFile.Cases {
		got := filepath.ToSlash(paths.JoinClean(c.ProjectDir, c.Relative))
		if got != c.WantSlash {
			return fmt.Errorf("%s: got %q want %q", c.Name, got, c.WantSlash)
		}
	}
	return nil
}

func assertMergePaths(root string, fx Fixture) error {
	var docs []*composeparse.Document
	for _, rel := range fx.Files {
		if !strings.HasSuffix(strings.ToLower(rel), ".yaml") && !strings.HasSuffix(strings.ToLower(rel), ".yml") && !strings.HasSuffix(strings.ToLower(rel), ".json") {
			continue
		}
		d, err := parseFile(root, rel)
		if err != nil {
			return err
		}
		docs = append(docs, d)
	}
	fields := merge.Documents(docs, nil)
	by := map[string]merge.Field{}
	for _, f := range fields {
		by[f.Path] = f
	}
	for _, pe := range fx.Expected.Local.Paths {
		got, ok := by[pe.Path]
		if pe.Action == merge.ActionReset {
			if !ok || got.Action != merge.ActionReset {
				return fmt.Errorf("%s action=%s want reset", pe.Path, got.Action)
			}
			continue
		}
		if pe.AbsentPath {
			if ok {
				return fmt.Errorf("%s should be absent", pe.Path)
			}
			continue
		}
		if !ok {
			return fmt.Errorf("missing merge path %s", pe.Path)
		}
		if pe.Value != "" && got.Value != pe.Value {
			return fmt.Errorf("%s value %q want %q", pe.Path, got.Value, pe.Value)
		}
		if pe.Action != "" && got.Action != pe.Action {
			return fmt.Errorf("%s action %s want %s", pe.Path, got.Action, pe.Action)
		}
	}
	return nil
}

func assertInterp(root string, fx Fixture) error {
	doc, err := parseFile(root, fx.Files[0])
	if err != nil {
		return err
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		return err
	}
	vals := interp.ResolveScalars(composeparse.StringScalars(doc), envGet(fx.Expected.Local.Env), fp)
	by := map[string]interp.Value{}
	for _, v := range vals {
		by[v.Path] = v
	}
	for _, pe := range fx.Expected.Local.Paths {
		got, ok := by[pe.Path]
		if !ok {
			return fmt.Errorf("missing interp path %s", pe.Path)
		}
		want := pe.Resolved
		if want == "" {
			want = pe.Value
		}
		if got.Resolved != want || (pe.State != "" && got.State != pe.State) {
			return fmt.Errorf("%s resolved=%q state=%s want %q %s", pe.Path, got.Resolved, got.State, want, pe.State)
		}
	}
	return nil
}

func assertProfiles(root string, fx Fixture) error {
	doc, err := parseFile(root, fx.Files[0])
	if err != nil {
		return err
	}
	fields := merge.Documents([]*composeparse.Document{doc}, nil)
	var environ []string
	for k, v := range fx.Expected.Local.HostEnv {
		environ = append(environ, k+"="+v)
	}
	active := profiles.Active(fx.Expected.Local.Profiles, environ)
	svcs := profiles.Activate(fields, active)
	by := map[string]profiles.Service{}
	for _, s := range svcs {
		by[s.Name] = s
	}
	for _, pe := range fx.Expected.Local.Paths {
		got, ok := by[pe.Path]
		if !ok {
			return fmt.Errorf("missing service %s", pe.Path)
		}
		if pe.State != "" && got.State != pe.State {
			return fmt.Errorf("%s state %s want %s", pe.Path, got.State, pe.State)
		}
		if pe.Certainty != "" && got.Certainty != pe.Certainty {
			return fmt.Errorf("%s certainty %s want %s", pe.Path, got.Certainty, pe.Certainty)
		}
	}
	return nil
}

func includeExpand(root string, fx Fixture) (include.Result, error) {
	entry := fx.Entry
	if entry == "" {
		entry = fx.Files[0]
	}
	doc, err := parseFile(root, entry)
	if err != nil {
		return include.Result{}, err
	}
	return include.Expand(doc, include.DiskLoad, nil), nil
}

func assertIncludeMerge(root string, fx Fixture) error {
	r, err := includeExpand(root, fx)
	if err != nil {
		return err
	}
	fields := merge.Documents(r.Docs, nil)
	by := map[string]merge.Field{}
	for _, f := range fields {
		by[f.Path] = f
	}
	for _, pe := range fx.Expected.Local.Paths {
		got, ok := by[pe.Path]
		if !ok {
			return fmt.Errorf("missing %s", pe.Path)
		}
		if pe.Value != "" && got.Value != pe.Value {
			return fmt.Errorf("%s value %q want %q", pe.Path, got.Value, pe.Value)
		}
	}
	return nil
}

func assertIncludeRef(root string, fx Fixture) error {
	r, err := includeExpand(root, fx)
	if err != nil {
		return err
	}
	if fx.Expected.Local.HasCycle != nil && r.Graph != nil {
		if r.Graph.HasCycle != *fx.Expected.Local.HasCycle {
			return fmt.Errorf("hasCycle=%t want %t", r.Graph.HasCycle, *fx.Expected.Local.HasCycle)
		}
	}
	if r.Graph == nil || len(r.Graph.Refs) == 0 {
		if fx.Expected.Local.HasCycle != nil && *fx.Expected.Local.HasCycle && r.Graph != nil && r.Graph.HasCycle {
			return nil
		}
		return fmt.Errorf("no include refs")
	}
	ref := r.Graph.Refs[0]
	if fx.Expected.Local.Form != "" && ref.Spec.Form != fx.Expected.Local.Form {
		return fmt.Errorf("form %s want %s", ref.Spec.Form, fx.Expected.Local.Form)
	}
	if fx.Expected.Local.State != "" && ref.State != fx.Expected.Local.State {
		return fmt.Errorf("state %s want %s", ref.State, fx.Expected.Local.State)
	}
	if fx.Expected.Local.Certainty != "" && ref.Certainty != fx.Expected.Local.Certainty {
		return fmt.Errorf("certainty %s want %s", ref.Certainty, fx.Expected.Local.Certainty)
	}
	if fx.Expected.Local.MinUnsupported > 0 && len(ref.Spec.UnsupportedFields) < fx.Expected.Local.MinUnsupported {
		return fmt.Errorf("unsupported fields %d want >= %d", len(ref.Spec.UnsupportedFields), fx.Expected.Local.MinUnsupported)
	}
	return nil
}

func extendsApply(root string, fx Fixture) (extends.Result, error) {
	entry := fx.Entry
	if entry == "" {
		entry = fx.Files[0]
	}
	doc, err := parseFile(root, entry)
	if err != nil {
		return extends.Result{}, err
	}
	return extends.Apply(doc, extends.DiskLoad, nil), nil
}

func assertExtendsField(root string, fx Fixture) error {
	r, err := extendsApply(root, fx)
	if err != nil {
		return err
	}
	by := map[string]merge.Field{}
	for _, f := range merge.Documents([]*composeparse.Document{r.Doc}, nil) {
		by[f.Path] = f
	}
	for _, pe := range fx.Expected.Local.Paths {
		if pe.AbsentPath {
			if _, ok := by[pe.Path]; ok {
				return fmt.Errorf("%s should be absent", pe.Path)
			}
			continue
		}
		got, ok := by[pe.Path]
		if !ok {
			return fmt.Errorf("missing %s", pe.Path)
		}
		if pe.Value != "" && got.Value != pe.Value {
			return fmt.Errorf("%s value %q want %q", pe.Path, got.Value, pe.Value)
		}
	}
	return nil
}

func assertExtendsRef(root string, fx Fixture) error {
	r, err := extendsApply(root, fx)
	if err != nil {
		return err
	}
	if fx.Expected.Local.HasCycle != nil {
		if r.Graph == nil || r.Graph.HasCycle != *fx.Expected.Local.HasCycle {
			return fmt.Errorf("cycle mismatch")
		}
		return nil
	}
	if r.Graph == nil {
		return fmt.Errorf("no extends graph")
	}
	for _, ref := range r.Graph.Refs {
		if fx.Expected.Local.Service != "" && ref.Name != fx.Expected.Local.Service {
			continue
		}
		if fx.Expected.Local.State != "" && ref.State != fx.Expected.Local.State {
			continue
		}
		return nil
	}
	return fmt.Errorf("no matching extends ref")
}

func assertContainerEnv(root string, fx Fixture) error {
	entry := fx.Entry
	if entry == "" {
		entry = fx.Files[0]
	}
	doc, err := parseFile(root, entry)
	if err != nil {
		return err
	}
	fields := merge.Documents([]*composeparse.Document{doc}, nil)
	host := fx.Expected.Local.HostEnv
	if host == nil {
		host = map[string]string{}
	}
	svcs, err := containerenv.Resolve(fields, host, nil)
	if err != nil {
		return err
	}
	svc := fx.Expected.Local.Service
	if svc == "" {
		svc = "web"
	}
	for _, se := range svcs {
		if se.Service != svc {
			continue
		}
		for _, v := range se.Vars {
			if v.Key != fx.Expected.Local.Key {
				continue
			}
			if fx.Expected.Local.Value != "" && v.Value != fx.Expected.Local.Value {
				return fmt.Errorf("%s=%q want %q", v.Key, v.Value, fx.Expected.Local.Value)
			}
			if fx.Expected.Local.State != "" && v.Winner.Kind != fx.Expected.Local.State {
				return fmt.Errorf("winner kind %s want %s", v.Winner.Kind, fx.Expected.Local.State)
			}
			return nil
		}
	}
	return fmt.Errorf("var %s not found", fx.Expected.Local.Key)
}

func assertCheckIDs(root string, fx Fixture) error {
	proj := fx.Expected.Local.Project
	if proj == "" {
		proj = filepath.ToSlash(filepath.Dir(fx.Files[0]))
	}
	in, err := loadProject(filepath.Join(root, filepath.FromSlash(proj)), []string{"compose.yaml"}, nil, nil, nil)
	if err != nil {
		return err
	}
	r := check.Evaluate(in)
	want := map[string]struct{}{}
	for _, id := range fx.Expected.Local.CheckIDs {
		want[id] = struct{}{}
	}
	got := map[string]struct{}{}
	for _, f := range r.Findings {
		got[f.ID] = struct{}{}
	}
	if len(want) == 0 && len(got) != 0 {
		return fmt.Errorf("clean expected 0 findings, got %v", keys(got))
	}
	for id := range want {
		if _, ok := got[id]; !ok {
			return fmt.Errorf("missing check %s (got %v)", id, keys(got))
		}
	}
	return nil
}

func assertNormalize(root string, fx Fixture, wantEqual bool) error {
	left, err := normalizeFrom(root, fx.Files[0])
	if err != nil {
		return err
	}
	rightRel := filepath.ToSlash(filepath.Join(filepath.FromSlash(fx.Expected.Local.Compare), "compose.yaml"))
	right, err := normalizeFrom(root, rightRel)
	if err != nil {
		return err
	}
	ls, _ := normalize.ServiceByName(left, "web")
	rs, _ := normalize.ServiceByName(right, "web")
	eq := familyEqual(ls, rs, fx.Expected.Local.Family)
	if eq != wantEqual {
		return fmt.Errorf("family %s equal=%t want %t", fx.Expected.Local.Family, eq, wantEqual)
	}
	return nil
}

func assertNormalizeUnknown(root string, fx Fixture) error {
	m, err := normalizeFrom(root, fx.Files[0])
	if err != nil {
		return err
	}
	s, ok := normalize.ServiceByName(m, "web")
	if !ok || len(s.Ports) == 0 {
		return fmt.Errorf("no ports")
	}
	if s.Ports[0].Provenance.Certainty != "unknown" {
		return fmt.Errorf("certainty %s want unknown", s.Ports[0].Provenance.Certainty)
	}
	return nil
}

func normalizeFrom(root, rel string) (normalize.Model, error) {
	doc, err := parseFile(root, rel)
	if err != nil {
		return normalize.Model{}, err
	}
	return normalize.FromMerge(merge.Documents([]*composeparse.Document{doc}, nil)), nil
}

func familyEqual(a, b normalize.Service, family string) bool {
	root := "services." + a.Name + "." + family
	if family == "healthcheck.test" {
		root = "services." + a.Name + ".healthcheck.test"
	}
	return normalize.FamilyEqual(a, b, root)
}

func loadProject(dir string, names, envFiles, flagProfiles, environ []string) (explain.Input, error) {
	fp, err := redact.NewFingerprinter()
	if err != nil {
		return explain.Input{}, err
	}
	table, err := interp.Load(dir, envFiles, dir, environ, fp)
	if err != nil {
		return explain.Input{}, err
	}
	var overlay []*composeparse.Document
	chains := map[string][]string{}
	var items []interp.Value
	seen := map[string]bool{}
	var includeGraphs []*include.Graph
	for _, name := range names {
		p := filepath.Join(dir, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			return explain.Input{}, err
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return explain.Input{}, err
		}
		doc, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
		if err != nil {
			return explain.Input{}, err
		}
		items = append(items, interp.ResolveScalars(composeparse.StringScalars(doc), table, fp)...)
		seen[doc.File.Path] = true
		expanded := include.Expand(doc, include.DiskLoad, table)
		overlay = append(overlay, expanded.Docs...)
		if expanded.Graph != nil {
			includeGraphs = append(includeGraphs, expanded.Graph)
		}
		for k, v := range expanded.Chains {
			if _, ok := chains[k]; !ok {
				chains[k] = v
			}
		}
		for _, d := range expanded.Docs {
			if d != nil && !seen[d.File.Path] {
				seen[d.File.Path] = true
				items = append(items, interp.ResolveScalars(composeparse.StringScalars(d), table, fp)...)
			}
		}
	}
	extOrigins := map[string]extends.Field{}
	var extGraphs []*extends.Graph
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.DiskLoad, table)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
		if er.Graph != nil {
			extGraphs = append(extGraphs, er.Graph)
		}
		for _, f := range er.Fields {
			extOrigins[f.Path] = f
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(flagProfiles, environ)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(environ), table)
	if err != nil {
		return explain.Input{}, err
	}
	return explain.Input{
		Interp:        items,
		Merge:         merged,
		Chains:        chains,
		Extends:       extOrigins,
		Profiles:      profiles.Activate(merged, active),
		Container:     cen,
		IncludeGraphs: includeGraphs,
		ExtendsGraphs: extGraphs,
	}, nil
}

func scanSecrets(root string, cat Catalog) error {
	seen := map[string]struct{}{}
	for _, fx := range cat.Fixtures {
		for _, rel := range fx.Files {
			if _, ok := seen[rel]; ok {
				continue
			}
			seen[rel] = struct{}{}
			raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
			if err != nil {
				return err
			}
			if redact.ContainsSecretMaterial(string(raw)) {
				return fmt.Errorf("secret-shaped material in %s", rel)
			}
		}
	}
	return nil
}

func keys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
