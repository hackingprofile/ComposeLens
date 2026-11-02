// SPDX-License-Identifier: Apache-2.0

package explain

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

func writeTree(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func snapshot(t *testing.T, dir string, names []string, environ, flagProfiles []string) Input {
	t.Helper()
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	table, err := interp.Load(dir, nil, dir, environ, fp)
	if err != nil {
		t.Fatal(err)
	}
	var overlay []*composeparse.Document
	chains := map[string][]string{}
	var items []interp.Value
	seen := map[string]bool{}
	for _, name := range names {
		p := filepath.Join(dir, name)
		raw, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			t.Fatal(err)
		}
		doc, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		items = append(items, interp.ResolveScalars(composeparse.StringScalars(doc), table, fp)...)
		seen[doc.File.Path] = true
		expanded := include.Expand(doc, include.DiskLoad, table)
		overlay = append(overlay, expanded.Docs...)
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
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.DiskLoad, table)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
		for _, f := range er.Fields {
			extOrigins[f.Path] = f
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(flagProfiles, environ)
	cen, err := containerenv.Resolve(merged, nil, table)
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Interp:    items,
		Merge:     merged,
		Chains:    chains,
		Extends:   extOrigins,
		Profiles:  profiles.Activate(merged, active),
		Container: cen,
	}
}

func stageNames(r Result) []string {
	var out []string
	for _, s := range r.Stages {
		out = append(out, s.Name)
	}
	return out
}

func fixtureSnapshot(t *testing.T, name string, files []string) Input {
	t.Helper()
	dir := filepath.Join("..", "..", "fixtures", "explain", name)
	return snapshot(t, dir, files, nil, nil)
}

func TestParseTargetKinds(t *testing.T) {
	svc, ok := ParseTarget("web", nil)
	if !ok || svc.Kind != KindService || svc.Service != "web" {
		t.Fatalf("%+v", svc)
	}
	f, ok := ParseTarget("services.web.image", nil)
	if !ok || f.Kind != KindField || f.Service != "web" || f.Path != "services.web.image" {
		t.Fatalf("%+v", f)
	}
	e, ok := ParseTarget("web:COLOR", nil)
	if !ok || e.Kind != KindEnv || e.Service != "web" || e.Key != "COLOR" {
		t.Fatalf("%+v", e)
	}
	if _, ok := ParseTarget("", nil); ok {
		t.Fatal("empty")
	}
	dotted, ok := ParseTarget("services.web.api.image", []string{"web.api"})
	if !ok || dotted.Kind != KindField || dotted.Service != "web.api" {
		t.Fatalf("%+v", dotted)
	}
}

func TestExplainEnvSpansInterpolationAndContainerEnv(t *testing.T) {
	r := Account("web:COLOR", fixtureSnapshot(t, "interp-env", []string{"compose.yaml"}))
	if r.State != StateOK || r.Effective != "teal" || r.FinalStage != StageContainerEnv {
		t.Fatalf("%+v", r)
	}
	names := strings.Join(stageNames(r), ",")
	if !strings.Contains(names, StageInterpolation) || !strings.Contains(names, StageContainerEnv) {
		t.Fatalf("stages %v", stageNames(r))
	}
	if i := indexOf(stageNames(r), StageInterpolation); i < 0 || indexOf(stageNames(r), StageContainerEnv) < i {
		t.Fatalf("order %v", stageNames(r))
	}
}

func TestExplainFieldSpansExtendsAndMerge(t *testing.T) {
	in := fixtureSnapshot(t, "extends-merge", []string{"compose.yaml", "overlay.yaml"})
	host := Account("services.app.hostname", in)
	if host.State != StateOK || host.Effective != "from-base" {
		t.Fatalf("hostname %+v", host)
	}
	names := strings.Join(stageNames(host), ",")
	if !strings.Contains(names, StageExtends) || !strings.Contains(names, StageMerge) {
		t.Fatalf("stages %v", stageNames(host))
	}
	found := false
	for _, s := range host.Stages {
		if s.Name == StageExtends && s.Origin == extends.OriginInherited {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected inherited %+v", host.Stages)
	}
	img := Account("services.app.image", in)
	if img.Effective != "nginx" {
		t.Fatalf("image %+v", img)
	}
}

func TestExplainProfileDisabledService(t *testing.T) {
	r := Account("debug", fixtureSnapshot(t, "profiles", []string{"compose.yaml"}))
	if r.State != StateOK || r.Effective != profiles.StateDisabled {
		t.Fatalf("%+v", r)
	}
	if len(r.Stages) != 1 || r.Stages[0].Name != StageProfiles {
		t.Fatalf("stages %+v", r.Stages)
	}
	if !strings.Contains(r.Stages[0].Reason, "disabled") {
		t.Fatalf("reason %s", r.Stages[0].Reason)
	}
}

func TestExplainSecretRedactedMaterial(t *testing.T) {
	secret := "synthetic-merge-token-overlay"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + secret + "\n",
	})
	r := Account("web:API_TOKEN", snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if !r.Secret || r.Effective != secret {
		t.Fatalf("%+v", r)
	}
	frags := SecretFragments(r)
	found := false
	for _, f := range frags {
		if strings.Contains(f, secret) {
			found = true
		}
	}
	if !found {
		t.Fatalf("fragments %v", frags)
	}
}

// A shadowed loser under a secret key is guard material and is carried as a
// value separate from its display line, so the view can withhold it while
// keeping the source label.
func TestExplainSecretLoserValuesAreGuardMaterial(t *testing.T) {
	loser := "firstsecretvalue"
	winner := "secondsecretvalue"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: .env.app\n    environment:\n      PASSWORD: " + winner + "\n",
		".env.app":     "PASSWORD=" + loser + "\n",
	})
	r := Account("web:PASSWORD", snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if r.State != StateOK || !r.Secret || r.Effective != winner {
		t.Fatalf("%+v", r)
	}
	var st Stage
	found := false
	for _, s := range r.Stages {
		if s.Name == StageContainerEnv {
			st, found = s, true
		}
	}
	if !found || !st.Secret {
		t.Fatalf("container stage %+v", r.Stages)
	}
	if len(st.Overridden) != 1 || len(st.OverriddenValues) != 1 {
		t.Fatalf("losers %+v %+v", st.Overridden, st.OverriddenValues)
	}
	if st.OverriddenValues[0] != loser || !strings.HasSuffix(st.Overridden[0], " "+loser) || !strings.HasPrefix(st.Overridden[0], containerenv.KindEnvFile+" ") {
		t.Fatalf("loser line %q value %q", st.Overridden[0], st.OverriddenValues[0])
	}
	frags := SecretFragments(r)
	gotLoser, gotWinner := false, false
	for _, f := range frags {
		if f == loser {
			gotLoser = true
		}
		if f == winner {
			gotWinner = true
		}
	}
	if !gotLoser || !gotWinner {
		t.Fatalf("guard material must hold winner and loser: %v", frags)
	}
}

// Merge losers of a secret-keyed field carry their values the same way.
func TestExplainMergeLoserValuesAreGuardMaterial(t *testing.T) {
	base := "basefilesecretvalue"
	over := "overridefilesecretvalue"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      DB_PASSWORD: " + base + "\n",
		"over.yaml":    "services:\n  web:\n    environment:\n      DB_PASSWORD: " + over + "\n",
	})
	r := Account("services.web.environment.DB_PASSWORD", snapshot(t, dir, []string{"compose.yaml", "over.yaml"}, nil, nil))
	if r.State != StateOK || !r.Secret || r.Effective != over {
		t.Fatalf("%+v", r)
	}
	var st Stage
	for _, s := range r.Stages {
		if s.Name == StageMerge {
			st = s
		}
	}
	if st.Name == "" || !st.Secret || len(st.Overridden) != 1 || len(st.OverriddenValues) != 1 || st.OverriddenValues[0] != base {
		t.Fatalf("merge stage %+v", st)
	}
	frags := SecretFragments(r)
	gotBase := false
	for _, f := range frags {
		if f == base {
			gotBase = true
		}
	}
	if !gotBase {
		t.Fatalf("merge loser missing from guard material: %v", frags)
	}
}

func TestExplainNonexistentTargetAbsent(t *testing.T) {
	in := fixtureSnapshot(t, "absent", []string{"compose.yaml"})
	for _, raw := range []string{"missing", "services.missing.image", "web:NOPE"} {
		r := Account(raw, in)
		if r.State != StateAbsent || len(r.Stages) != 0 || r.Effective != "" {
			t.Fatalf("%s %+v", raw, r)
		}
	}
}

func TestExplainDottedServiceRoundTrip(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web.api:\n    image: nginx:1.25\n    environment:\n      FOO: bar\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, []string{"COMPOSE_PROJECT_NAME=identity-dotted"}, []string{"unused-profile"})
	r := Account("web.api", in)
	if r.State != StateOK || r.Target.Service != "web.api" || r.Effective == "" || len(r.Stages) == 0 {
		t.Fatalf("service %+v", r)
	}
	if strings.Contains(r.Effective, "web") && r.Target.Service != "web.api" {
		t.Fatal("truncated")
	}
	img := Account("services.web.api.image", in)
	if img.State != StateOK || img.Target.Service != "web.api" || img.Effective != "nginx:1.25" || len(img.Stages) == 0 {
		t.Fatalf("field %+v", img)
	}
	env := Account("web.api:FOO", in)
	if env.State != StateOK || env.Target.Service != "web.api" || env.Effective != "bar" {
		t.Fatalf("env %+v", env)
	}
	for _, p := range in.Profiles {
		if p.Name != "web.api" {
			t.Fatalf("profile name %q", p.Name)
		}
	}
}

func TestExplainCollisionDistinct(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      FOO: from-web\n  web.api:\n    image: nginx:1.25\n    environment:\n      FOO: from-api\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil, nil)
	web := Account("web", in)
	api := Account("web.api", in)
	if web.State != StateOK || api.State != StateOK || web.Target.Service == api.Target.Service {
		t.Fatalf("web=%+v api=%+v", web, api)
	}
	wImg := Account("services.web.image", in)
	aImg := Account("services.web.api.image", in)
	if wImg.Effective != "alpine" || aImg.Effective != "nginx:1.25" {
		t.Fatalf("images %q %q", wImg.Effective, aImg.Effective)
	}
	if Account("web:FOO", in).Effective != "from-web" || Account("web.api:FOO", in).Effective != "from-api" {
		t.Fatal("env absorbed")
	}
	names := map[string]bool{}
	for _, p := range in.Profiles {
		names[p.Name] = true
	}
	if !names["web"] || !names["web.api"] || len(names) != 2 {
		t.Fatalf("profiles %v", names)
	}
}

func TestReservedPrefixServiceStaysOwnEntity(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:web\n  \"services.web\":\n    image: alpine:reserved\n    profiles: [off]\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil, nil)
	reserved := Account("services.web", in)
	if reserved.State != StateOK || reserved.Target.Kind != KindService || reserved.Target.Service != "services.web" {
		t.Fatalf("reserved service %+v", reserved)
	}
	var disabled bool
	for _, st := range reserved.Stages {
		if st.Name == StageProfiles && st.State != profiles.StateEnabled {
			disabled = true
		}
	}
	if !disabled {
		t.Fatalf("profile-disabled services.web inherited web: %+v", reserved)
	}
	web := Account("web", in)
	if web.Target.Service != "web" || web.State != StateOK {
		t.Fatalf("web %+v", web)
	}
	img := Account("services.web.image", in)
	if img.State != StateOK || img.Target.Kind != KindField || img.Target.Service != "web" || img.Effective != "alpine:web" {
		t.Fatalf("web image %+v", img)
	}
}

func TestDottedServiceDoesNotAbsorbFieldPath(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:web\n  \"web.image\":\n    image: alpine:dotted\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil, nil)
	field := Account("services.web.image", in)
	if field.State != StateOK || field.Target.Kind != KindField || field.Target.Service != "web" || field.Effective != "alpine:web" {
		t.Fatalf("web image field %+v", field)
	}
	svc := Account("web.image", in)
	if svc.State != StateOK || svc.Target.Kind != KindService || svc.Target.Service != "web.image" {
		t.Fatalf("dotted service %+v", svc)
	}
	own := Account("services.web.image.image", in)
	if own.State != StateOK || own.Target.Kind != KindField || own.Target.Service != "web.image" || own.Effective != "alpine:dotted" {
		t.Fatalf("dotted service image %+v", own)
	}
}

func TestReservedPrefixEnvTarget(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  \"services.web\":\n    image: alpine:3.21.3\n    environment:\n      APP_ENV: demonstration\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil, nil)
	env := Account("services.web:APP_ENV", in)
	if env.State != StateOK || env.Target.Kind != KindEnv || env.Target.Service != "services.web" || env.Target.Key != "APP_ENV" || env.Effective != "demonstration" {
		t.Fatalf("env target %+v", env)
	}
	field := Account("services.services.web.image", in)
	if field.State != StateOK || field.Target.Kind != KindField || field.Target.Service != "services.web" {
		t.Fatalf("field %+v", field)
	}
}

func TestCombinedServiceFieldCollisionAmbiguousCLI(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:3.21.3\n  \"services.web.image\":\n    image: alpine:3.19\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil, nil)
	cli := Account("services.web.image", in)
	if cli.State != StateAbsent || cli.Reason != "target matches more than one entity" {
		t.Fatalf("ambiguous CLI %+v", cli)
	}
	web := Account("web", in)
	if web.State != StateOK || web.Target.Kind != KindService || web.Target.Service != "web" {
		t.Fatalf("web %+v", web)
	}
	named := Account("services.web.image", in)
	if named.State != StateAbsent {
		t.Fatalf("textual collision must stay absent %+v", named)
	}
	own := AccountResolved(Target{Raw: "services.web.image", Kind: KindService, Service: "services.web.image"}, in)
	if own.State != StateOK || own.Target.Kind != KindService || own.Target.Service != "services.web.image" {
		t.Fatalf("resolved service %+v", own)
	}
	field := AccountResolved(Target{Raw: "services.web.image", Kind: KindField, Service: "web", Path: "services.web.image"}, in)
	if field.State != StateOK || field.Target.Kind != KindField || field.Effective != "alpine:3.21.3" {
		t.Fatalf("resolved field %+v", field)
	}
}

func indexOf(ss []string, v string) int {
	for i, s := range ss {
		if s == v {
			return i
		}
	}
	return -1
}
