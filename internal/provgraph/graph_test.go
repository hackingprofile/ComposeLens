// SPDX-License-Identifier: Apache-2.0

package provgraph

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
	"composelens/internal/safety"
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

func snapshot(t *testing.T, dir string, names, envFiles []string) Input {
	t.Helper()
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	table, err := interp.Load(dir, envFiles, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
	}
	binds, err := envsrc.Collect(dir, envFiles, dir, nil, fp)
	if err != nil {
		t.Fatal(err)
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
		if er.Graph != nil && (er.Graph.HasCycle || len(er.Graph.Refs) > 0) {
			extGraphs = append(extGraphs, er.Graph)
		}
		for _, f := range er.Fields {
			extOrigins[f.Path] = f
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(nil, nil)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(nil), table)
	if err != nil {
		t.Fatal(err)
	}
	return Input{
		Model: explain.Input{
			Interp:        items,
			Merge:         merged,
			Chains:        chains,
			Extends:       extOrigins,
			Profiles:      profiles.Activate(merged, active),
			Container:     cen,
			IncludeGraphs: includeGraphs,
			ExtendsGraphs: extGraphs,
		},
		Env: binds,
	}
}

func shadowFixture(t *testing.T) Input {
	t.Helper()
	dir := filepath.Join("..", "..", "fixtures", "graph", "shadow-chain")
	return snapshot(t, dir, []string{"compose.yaml"}, []string{"extra.env"})
}

func nodeBy(g Graph, target string) (Node, bool) {
	for _, n := range g.Nodes {
		if n.Target == target {
			return n, true
		}
	}
	return Node{}, false
}

func TestMultiStageShadowChain(t *testing.T) {
	g := Assemble(shadowFixture(t))
	n, ok := nodeBy(g, "web:COLOR")
	if !ok {
		t.Fatalf("missing web:COLOR in %+v", targets(g))
	}
	if n.State != explain.StateOK || n.Kind != KindEnv {
		t.Fatalf("%+v", n)
	}
	if n.Secret {
		t.Fatal("demo COLOR should not be secret")
	}
	if n.Effective != "from-env-file" {
		t.Fatalf("effective %q", n.Effective)
	}
	if !hasRoleStage(n, RoleWinner, explain.StageInterpolation, evidence.StageEnvFile) {
		t.Fatalf("missing env-file winner: %+v", n.Chain)
	}
	if !hasRoleStage(n, RoleShadowed, explain.StageContainerEnv, containerenv.KindEnvFile) {
		t.Fatalf("missing container env_file loser: %+v", n.Chain)
	}
	if !hasRoleStage(n, RoleWinner, explain.StageContainerEnv, containerenv.KindEnvironment) {
		t.Fatalf("missing environment winner: %+v", n.Chain)
	}
	if stageApplies(n, explain.StageInterpolation) && fabricated(n) {
		t.Fatalf("fabricated links %+v", n.Chain)
	}
	hn, ok := nodeBy(g, "services.web.hostname")
	if !ok {
		t.Fatal("missing hostname field")
	}
	if !hasRoleStage(hn, RoleWinner, explain.StageInterpolation, evidence.StageEnvFile) {
		t.Fatalf("hostname missing env-file winner %+v", hn.Chain)
	}
}

func TestWholeModelCoverage(t *testing.T) {
	g := Assemble(shadowFixture(t))
	need := []string{"web", "worker", "services.web.hostname", "services.web.image", "services.worker.image", "web:COLOR"}
	for _, tname := range need {
		if _, ok := nodeBy(g, tname); !ok {
			t.Fatalf("missing %s in %v", tname, targets(g))
		}
	}
	if _, ok := nodeBy(g, "services.web.environment.COLOR"); ok {
		t.Fatal("environment map duplicated as a field node")
	}
	if Lookup(g, "missing").State != explain.StateAbsent {
		t.Fatal("lookup fabricated a present node")
	}
	if Lookup(g, "missing").Chain != nil {
		t.Fatal("absent lookup fabricated a chain")
	}
	if _, ok := nodeBy(g, "missing"); ok {
		t.Fatal("graph contains a nonexistent target")
	}
}

func TestTypedStatesPreserved(t *testing.T) {
	g := Assemble(shadowFixture(t))
	n, ok := nodeBy(g, "web")
	if !ok {
		t.Fatal("missing web")
	}
	found := false
	for _, l := range n.Chain {
		if l.Stage == explain.StageProfiles && l.State == "enabled" {
			found = true
		}
	}
	if !found {
		t.Fatalf("profiles typed state missing %+v", n.Chain)
	}
}

func fieldVsEnvInput(t *testing.T) Input {
	t.Helper()
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  fieldsvc:\n    image: ${TINT}\n  envsvc:\n    image: static\n    environment:\n      - COLOR=${TINT}\n",
		".env":         "TINT=dotenv-tint\n",
		"overlay.env":  "TINT=overlay-tint\n",
	})
	return snapshot(t, dir, []string{"compose.yaml"}, []string{"overlay.env"})
}

func TestEnvNodeInterpLosersMatchField(t *testing.T) {
	g := Assemble(fieldVsEnvInput(t))
	field, ok := nodeBy(g, "services.fieldsvc.image")
	if !ok {
		t.Fatalf("missing field node in %v", targets(g))
	}
	env, ok := nodeBy(g, "envsvc:COLOR")
	if !ok {
		t.Fatalf("missing env node in %v", targets(g))
	}
	if field.Effective != "overlay-tint" || env.Effective != "overlay-tint" {
		t.Fatalf("effective field=%q env=%q", field.Effective, env.Effective)
	}
	if !hasRoleStage(field, RoleWinner, explain.StageInterpolation, evidence.StageEnvFile) {
		t.Fatalf("field missing env-file winner %+v", field.Chain)
	}
	if !hasRoleStage(env, RoleWinner, explain.StageInterpolation, evidence.StageEnvFile) {
		t.Fatalf("env-node missing env-file winner %+v", env.Chain)
	}
}

func TestEnvNodeNoFabricatedInterpLoser(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  envsvc:\n    image: static\n    environment:\n      - COLOR=${TINT}\n",
		".env":         "TINT=only-project-env\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	n, ok := nodeBy(g, "envsvc:COLOR")
	if !ok {
		t.Fatalf("missing envsvc:COLOR in %v", targets(g))
	}
	if n.Effective != "only-project-env" {
		t.Fatalf("effective %q", n.Effective)
	}
	if hasRoleStage(n, RoleShadowed, explain.StageInterpolation, evidence.StageEnvFile) {
		t.Fatalf("invented env-file loser %+v", n.Chain)
	}
	if hasRoleStage(n, RoleShadowed, explain.StageInterpolation, evidence.StageHost) {
		t.Fatalf("invented host-shell loser %+v", n.Chain)
	}
	if !hasRoleStage(n, RoleWinner, explain.StageInterpolation, evidence.StageProject) {
		t.Fatalf("missing project-env winner %+v", n.Chain)
	}
	shadowed := 0
	for _, l := range n.Chain {
		if l.Stage == explain.StageInterpolation && l.Role == RoleShadowed {
			shadowed++
		}
	}
	if shadowed != 0 {
		t.Fatalf("invented interpolation losers %+v", n.Chain)
	}
}

func TestEnvNodeListFormSecretRedacted(t *testing.T) {
	const probe = "ghp_ComposeLensGraphProbe99"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  envsvc:\n    image: alpine\n    environment:\n      - API_TOKEN=${API_TOKEN}\n",
		".env":         "API_TOKEN=" + probe + "\n",
		"extra.env":    "API_TOKEN=" + probe + "-file\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, []string{"extra.env"}))
	n, ok := nodeBy(g, "envsvc:API_TOKEN")
	if !ok {
		t.Fatalf("missing envsvc:API_TOKEN in %v", targets(g))
	}
	if !n.Secret {
		t.Fatal("expected secret node")
	}
	raw, err := JSON(g)
	if err != nil {
		t.Fatal(err)
	}
	blob := string(raw) + Human(g)
	if strings.Contains(blob, probe) || strings.Contains(blob, probe+"-file") {
		t.Fatal("raw secret leaked in list-form env-node graph")
	}
}

func TestSecretThroughChainRedacted(t *testing.T) {
	const probe = "ghp_ComposeLensGraphProbe99"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${API_TOKEN}\n",
		".env":         "API_TOKEN=" + probe + "\n",
		"extra.env":    "API_TOKEN=" + probe + "-file\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, []string{"extra.env"})
	g := Assemble(in)
	n, ok := nodeBy(g, "web:API_TOKEN")
	if !ok {
		t.Fatalf("missing web:API_TOKEN in %v", targets(g))
	}
	if !n.Secret {
		t.Fatal("expected secret node")
	}
	raw, err := JSON(g)
	if err != nil {
		t.Fatal(err)
	}
	human := Human(g)
	blob := string(raw) + human
	if strings.Contains(blob, probe) || strings.Contains(blob, probe+"-file") {
		t.Fatal("raw secret leaked in graph JSON or human")
	}
	rep := NewReport(g)
	for _, nr := range rep.Nodes {
		if nr.Target == "web:API_TOKEN" {
			if nr.Effective != nil {
				t.Fatalf("effective leaked %+v", nr.Effective)
			}
			if !nr.Secret {
				t.Fatal("json secret flag false")
			}
		}
	}
	if !strings.Contains(human, "[redacted]") {
		t.Fatal("human did not redact")
	}
}

func TestHumanShowsDigitServiceIdentities(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  my-application-service-v2:\n    image: alpine\n  payment-gateway-worker-01:\n    image: alpine\n    environment:\n      COLOR: teal\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	human := Human(g)
	for _, id := range []string{
		"services.my-application-service-v2.image",
		"services.payment-gateway-worker-01.image",
		"payment-gateway-worker-01:COLOR",
	} {
		if !strings.Contains(human, id) {
			t.Fatalf("human missing identity %q:\n%s", id, human)
		}
	}
	if strings.Contains(human, "[redacted]") {
		t.Fatalf("human over-redacted identities:\n%s", human)
	}
}

func TestHumanRedactsSecretShapedPaths(t *testing.T) {
	g := Graph{Nodes: []Node{{
		Target: "web", Kind: KindService, State: explain.StateOK,
		Chain: []Link{{Order: 1, Role: RoleWinner, Stage: explain.StageMerge, Source: "ghp_abcdefghijklmnopqrstuvwxyz0123456789"}},
	}}}
	h := Human(g)
	if strings.Contains(h, "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatalf("human printed secret: %s", h)
	}
	if !strings.Contains(h, "[redacted]") {
		t.Fatalf("expected redaction: %s", h)
	}
}

func TestJSONSchemaAndNoFabricationWithoutBinds(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil)
	in.Env = nil
	g := Assemble(in)
	raw, err := JSON(g)
	if err != nil {
		t.Fatal(err)
	}
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != Schema || !strings.Contains(rep.Disclaimer, "not a new resolver") {
		t.Fatalf("%+v", rep)
	}
	n, ok := nodeBy(g, "services.web.image")
	if !ok {
		t.Fatal("missing image")
	}
	for _, l := range n.Chain {
		if l.Stage == explain.StageInterpolation && strings.Contains(l.Source, evidence.StageProject) {
			t.Fatal("fabricated project-env interpolation loser without bindings")
		}
	}
}

func TestAccountUnchangedByGraph(t *testing.T) {
	in := shadowFixture(t)
	acc := explain.Account("web:COLOR", in.Model)
	if acc.Effective != "from-env-file" || acc.State != explain.StateOK {
		t.Fatalf("%+v", acc)
	}
	g := Assemble(in)
	n, _ := nodeBy(g, "web:COLOR")
	if n.Effective != acc.Effective || n.Secret != acc.Secret || n.FinalStage != acc.FinalStage {
		t.Fatalf("graph drifted from account graph=%+v acc=%+v", n, acc)
	}
}

func TestSecretFragmentsSkipNonSecretIdentities(t *testing.T) {
	names := []string{
		"svc-javascript:alert(1)",
		"svc-python:print(1)",
		"xxx-javascript:alert(9)",
		"web.api",
		"abcdefghijklmnopqrstuvwxyz0123",
		"svc-αβγδεζηθ",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			dir := writeTree(t, map[string]string{
				"compose.yaml": "services:\n  \"" + name + "\":\n    image: alpine\n    labels:\n      x: \"foo:bar(1)\"\n",
			})
			g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
			frags := SecretFragments(g)
			for _, frag := range frags {
				if strings.Contains(frag, name) || strings.Contains(frag, "foo:bar(1)") {
					t.Fatalf("non-secret identity/value in Guard material: %q from %v", frag, frags)
				}
			}
			raw, err := JSON(g)
			if err != nil {
				t.Fatal(err)
			}
			if err := safety.Guard(raw, frags); err != nil {
				t.Fatalf("guard false-closed on identity: %v", err)
			}
		})
	}
}

func TestSecretFragmentsIgnoreSyntheticMarkerInPlainValue(t *testing.T) {
	image := "registry.example.test/synthetic-data:1.0"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: " + image + "\n    labels:\n      note: synthetic-fixture\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	frags := SecretFragments(g)
	for _, frag := range frags {
		if strings.Contains(frag, "synthetic-") {
			t.Fatalf("non-secret marker value in Guard material: %q from %v", frag, frags)
		}
	}
	raw, err := JSON(g)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), image) {
		t.Fatal("graph JSON must display the non-secret image")
	}
	if err := safety.Guard(raw, frags); err != nil {
		t.Fatalf("guard false-closed on marker value: %v", err)
	}
}

func TestSecretFragmentsGenuineStillCaught(t *testing.T) {
	const probe = "ghp_ComposeLensGraphProbe99"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	frags := SecretFragments(g)
	found := false
	for _, frag := range frags {
		if strings.Contains(frag, probe) {
			found = true
		}
	}
	if !found {
		t.Fatalf("genuine secret missing from Guard material: %v", frags)
	}
	raw, err := JSON(g)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), probe) {
		t.Fatal("raw secret leaked in graph JSON")
	}
	if err := safety.Guard(raw, frags); err != nil {
		t.Fatalf("redacted graph must not fail-close: %v", err)
	}
	leaked := append(append([]byte(nil), raw...), probe...)
	if err := safety.Guard(leaked, frags); err == nil {
		t.Fatal("Guard must still fail-close when a genuine secret would leak")
	} else if !strings.Contains(err.Error(), "a secret value would leak") {
		t.Fatalf("want leak message, got %v", err)
	}
}

func targets(g Graph) []string {
	out := make([]string, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		out = append(out, n.Target)
	}
	return out
}

func hasRoleStage(n Node, role, stage, kindOrSource string) bool {
	for _, l := range n.Chain {
		if l.Role != role || l.Stage != stage {
			continue
		}
		if l.Kind == kindOrSource || strings.Contains(l.Source, kindOrSource) {
			return true
		}
	}
	return false
}

func stageApplies(n Node, stage string) bool {
	for _, l := range n.Chain {
		if l.Stage == stage {
			return true
		}
	}
	return false
}

func fabricated(n Node) bool {
	for _, l := range n.Chain {
		if l.Source == "" && l.Kind == "" && l.State == "" {
			return true
		}
	}
	return false
}

func TestProjectNameIsNotAServiceNode(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "name: demo-project\nservices:\n  app:\n    image: alpine\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil)
	hasName := false
	for _, f := range in.Model.Merge {
		if f.Path == "name" && f.Value == "demo-project" {
			hasName = true
		}
	}
	if !hasName {
		t.Fatal("project name: missing from the merge model")
	}
	g := Assemble(in)
	if _, ok := nodeBy(g, "name"); ok {
		t.Fatalf("phantom name node in %v", targets(g))
	}
	n, ok := nodeBy(g, "app")
	if !ok || n.Kind != KindService || n.State != explain.StateOK {
		t.Fatalf("app node %+v ok=%v", n, ok)
	}
	rep := NewReport(g)
	if rep.Counts.Services != 1 {
		t.Fatalf("graph services=%d want 1 in %v", rep.Counts.Services, targets(g))
	}
}

func TestServiceIdentitiesDoNotCollide(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "name: demo-project\nservices:\n  app:\n    image: alpine\n    command: echo hi\n  app2:\n    image: alpine\n  app.worker:\n    image: alpine\n  name:\n    image: alpine\n",
	})
	in := snapshot(t, dir, []string{"compose.yaml"}, nil)
	hasName := false
	for _, f := range in.Model.Merge {
		if f.Path == "name" && f.Value == "demo-project" {
			hasName = true
		}
	}
	if !hasName {
		t.Fatal("project name: missing from the merge model")
	}
	g := Assemble(in)
	for _, want := range []string{"app", "app2", "app.worker", "name"} {
		n, ok := nodeBy(g, want)
		if !ok || n.Kind != KindService || n.State == explain.StateAbsent {
			t.Fatalf("%s: ok=%v %+v in %v", want, ok, n, targets(g))
		}
	}
	if _, ok := nodeBy(g, "services.app.command"); !ok {
		t.Fatal("app command field missing")
	}
	if _, ok := nodeBy(g, "services.app2.command"); ok {
		t.Fatal("app2 has no command field")
	}
	rep := NewReport(g)
	if rep.Counts.Services != 4 {
		t.Fatalf("graph services=%d want 4", rep.Counts.Services)
	}
}

func TestReservedPrefixServiceNode(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:web\n  \"services.web\":\n    image: alpine:reserved\n    profiles: [off]\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	n, ok := nodeBy(g, "services.web")
	if !ok || n.Kind != KindService || n.State == explain.StateAbsent {
		t.Fatalf("services.web %+v ok=%v in %v", n, ok, targets(g))
	}
	web, ok := nodeBy(g, "web")
	if !ok || web.Kind != KindService {
		t.Fatalf("web %+v", web)
	}
	img, ok := nodeBy(g, "services.web.image")
	if !ok || img.Kind != KindField || img.Effective != "alpine:web" {
		t.Fatalf("web image %+v ok=%v", img, ok)
	}
}

func TestDottedServiceKeepsOwnImageNode(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:web\n  \"web.image\":\n    image: alpine:dotted\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	webImg, ok := nodeBy(g, "services.web.image")
	if !ok || webImg.Kind != KindField || webImg.Effective != "alpine:web" {
		t.Fatalf("web.image field %+v ok=%v in %v", webImg, ok, targets(g))
	}
	svc, ok := nodeBy(g, "web.image")
	if !ok || svc.Kind != KindService {
		t.Fatalf("service web.image %+v ok=%v", svc, ok)
	}
	own, ok := nodeBy(g, "services.web.image.image")
	if !ok || own.Kind != KindField || own.Effective != "alpine:dotted" {
		t.Fatalf("dotted image field %+v ok=%v in %v", own, ok, targets(g))
	}
}

func nodeByKind(g Graph, target, kind string) (Node, bool) {
	for _, n := range g.Nodes {
		if n.Target == target && n.Kind == kind {
			return n, true
		}
	}
	return Node{}, false
}

func TestCombinedServiceFieldCollisionKeepsBoth(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:3.21.3\n  \"services.web.image\":\n    image: alpine:3.19\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	web, ok := nodeByKind(g, "web", KindService)
	if !ok || web.State == explain.StateAbsent {
		t.Fatalf("web service %+v ok=%v in %v", web, ok, targets(g))
	}
	named, ok := nodeByKind(g, "services.web.image", KindService)
	if !ok || named.State == explain.StateAbsent {
		t.Fatalf("named service %+v ok=%v in %v", named, ok, targets(g))
	}
	webImg, ok := nodeByKind(g, "services.web.image", KindField)
	if !ok || webImg.Effective != "alpine:3.21.3" {
		t.Fatalf("web image field %+v ok=%v", webImg, ok)
	}
	own, ok := nodeByKind(g, "services.services.web.image.image", KindField)
	if !ok || own.Effective != "alpine:3.19" {
		t.Fatalf("named service image %+v ok=%v in %v", own, ok, targets(g))
	}
	rep := NewReport(g)
	if rep.Counts.Services != 2 {
		t.Fatalf("services=%d", rep.Counts.Services)
	}
	if rep.Counts.Fields < 2 {
		t.Fatalf("fields=%d", rep.Counts.Fields)
	}
	for _, n := range g.Nodes {
		if n.State == explain.StateAbsent {
			t.Fatalf("unexpected absent node %+v", n)
		}
	}
	hit := Lookup(g, "services.web.image")
	if hit.State != explain.StateAbsent || hit.Reason != "target matches more than one entity" {
		t.Fatalf("textual lookup %+v", hit)
	}
	if LookupKind(g, "services.web.image", KindField).Effective != "alpine:3.21.3" {
		t.Fatal("kind lookup field")
	}
}

func TestReservedPrefixEnvGraphNode(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  \"services.web\":\n    image: alpine:3.21.3\n    environment:\n      APP_ENV: demonstration\n",
	})
	g := Assemble(snapshot(t, dir, []string{"compose.yaml"}, nil))
	svc, ok := nodeByKind(g, "services.web", KindService)
	if !ok || svc.State == explain.StateAbsent {
		t.Fatalf("service %+v ok=%v in %v", svc, ok, targets(g))
	}
	env, ok := nodeByKind(g, "services.web:APP_ENV", KindEnv)
	if !ok || env.Effective != "demonstration" {
		t.Fatalf("env %+v ok=%v in %v", env, ok, targets(g))
	}
	rep := NewReport(g)
	if rep.Counts.Services != 1 || rep.Counts.Env != 1 {
		t.Fatalf("counts services=%d env=%d nodes=%v", rep.Counts.Services, rep.Counts.Env, targets(g))
	}
}
