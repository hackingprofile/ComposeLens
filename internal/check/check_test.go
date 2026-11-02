// SPDX-License-Identifier: Apache-2.0

package check

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/envsrc"
	"composelens/internal/explain"
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

func snapshot(t *testing.T, dir string, names, flagProfiles []string, environ []string) explain.Input {
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
	active := profiles.Active(flagProfiles, environ)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(environ), table)
	if err != nil {
		t.Fatal(err)
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
	}
}

func fixture(t *testing.T, name string) explain.Input {
	t.Helper()
	dir := filepath.Join("..", "..", "fixtures", "check", name)
	return snapshot(t, dir, []string{"compose.yaml"}, nil, nil)
}

func ids(r Result) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range r.Findings {
		if _, ok := seen[f.ID]; ok {
			continue
		}
		seen[f.ID] = struct{}{}
		out = append(out, f.ID)
	}
	sort.Strings(out)
	return out
}

func hasID(r Result, id string) bool {
	for _, f := range r.Findings {
		if f.ID == id {
			return true
		}
	}
	return false
}

func TestCleanZeroFindings(t *testing.T) {
	r := Evaluate(fixture(t, "clean"))
	if len(r.Findings) != 0 {
		t.Fatalf("clean findings %+v", r.Findings)
	}
}

func TestCHK01SecretInlineFiresAndNotOnClean(t *testing.T) {
	r := Evaluate(fixture(t, "secret-inline"))
	if !hasID(r, CHK01) {
		t.Fatalf("expected CHK01, got %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.ID != CHK01 {
			t.Fatalf("secret-inline should only fire CHK01, got %+v", r.Findings)
		}
		if f.Target != "web:API_TOKEN" || f.Severity != SevWarning {
			t.Fatalf("%+v", f)
		}
		if strings.Contains(f.Message, "demo-inline") {
			t.Fatal("inline value leaked in message")
		}
	}
	clean := Evaluate(fixture(t, "clean"))
	if hasID(clean, CHK01) {
		t.Fatalf("CHK01 false-fired on clean: %+v", clean.Findings)
	}
}

func TestCHK02RequiredUnsetFiresAndNotOnClean(t *testing.T) {
	r := Evaluate(fixture(t, "required-unset"))
	if !hasID(r, CHK02) {
		t.Fatalf("expected CHK02, got %+v", r.Findings)
	}
	for _, f := range r.Findings {
		if f.ID != CHK02 || f.Severity != SevError {
			t.Fatalf("%+v", r.Findings)
		}
	}
	clean := Evaluate(fixture(t, "clean"))
	if hasID(clean, CHK02) {
		t.Fatalf("CHK02 false-fired on clean: %+v", clean.Findings)
	}
}

func TestCHK03ProfiledDependencyGapFiresAndNotOnOrdinaryDisabled(t *testing.T) {
	r := Evaluate(fixture(t, "profiled-dep"))
	if !hasID(r, CHK03) {
		t.Fatalf("expected CHK03, got %+v", r.Findings)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == CHK03 && f.Target == "db" && f.Severity == SevWarning {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", r.Findings)
	}
	dir := filepath.Join("..", "..", "fixtures", "profiles")
	ordinary := snapshot(t, dir, []string{"official.yaml"}, nil, nil)
	or := Evaluate(ordinary)
	if hasID(or, CHK03) {
		t.Fatalf("CHK03 false-fired on ordinary profile-disabled service: %+v", or.Findings)
	}
	clean := Evaluate(fixture(t, "clean"))
	if hasID(clean, CHK03) {
		t.Fatalf("CHK03 false-fired on clean: %+v", clean.Findings)
	}
	enabled := snapshot(t, filepath.Join("..", "..", "fixtures", "check", "profiled-dep"), []string{"compose.yaml"}, []string{"storage"}, nil)
	if hasID(Evaluate(enabled), CHK03) {
		t.Fatalf("CHK03 false-fired when profile storage is active")
	}
}

func TestCHK04MissingIncludeAndExtendsAndNotCycle(t *testing.T) {
	inc := Evaluate(fixture(t, "missing-include"))
	if !hasID(inc, CHK04) {
		t.Fatalf("expected CHK04 include, got %+v", inc.Findings)
	}
	ext := Evaluate(fixture(t, "missing-extends"))
	if !hasID(ext, CHK04) {
		t.Fatalf("expected CHK04 extends, got %+v", ext.Findings)
	}
	cycleDir := filepath.Join("..", "..", "fixtures", "include", "cycle")
	cycle := Evaluate(snapshot(t, cycleDir, []string{"a.yaml"}, nil, nil))
	if hasID(cycle, CHK04) {
		t.Fatalf("CHK04 false-fired on include cycle: %+v", cycle.Findings)
	}
	clean := Evaluate(fixture(t, "clean"))
	if hasID(clean, CHK04) {
		t.Fatalf("CHK04 false-fired on clean: %+v", clean.Findings)
	}
}

func TestCHK05EnvShadowingFiresAndNotOnSingleSource(t *testing.T) {
	r := Evaluate(fixture(t, "env-shadowing"))
	if !hasID(r, CHK05) {
		t.Fatalf("expected CHK05, got %+v", r.Findings)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == CHK05 && f.Target == "web:COLOR" && f.Severity == SevInfo {
			found = true
		}
	}
	if !found {
		t.Fatalf("%+v", r.Findings)
	}
	clean := Evaluate(fixture(t, "clean"))
	if hasID(clean, CHK05) {
		t.Fatalf("CHK05 false-fired on clean: %+v", clean.Findings)
	}
}

func TestFormatsAgreeAndSARIFValid(t *testing.T) {
	in := fixture(t, "env-shadowing")
	r := Evaluate(in)
	human := Human(r)
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSARIF(sarif); err != nil {
		t.Fatal(err)
	}
	hf := FingerprintsFromHuman(human)
	jf, err := FingerprintsFromJSON(js)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := FingerprintsFromSARIF(sarif)
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(hf)
	sort.Strings(jf)
	sort.Strings(sf)
	want := Fingerprints(r)
	if strings.Join(hf, ";") != strings.Join(want, ";") || strings.Join(jf, ";") != strings.Join(want, ";") || strings.Join(sf, ";") != strings.Join(want, ";") {
		t.Fatalf("disagree human=%v json=%v sarif=%v engine=%v", hf, jf, sf, want)
	}
}

func TestSARIFSchemaValidOnEachFixture(t *testing.T) {
	for _, name := range []string{"clean", "secret-inline", "inline-default", "external-ref", "nonsecret-default", "required-unset", "profiled-dep", "missing-include", "missing-extends", "env-shadowing"} {
		r := Evaluate(fixture(t, name))
		raw, err := SARIF(r)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if err := ValidateSARIF(raw); err != nil {
			t.Fatalf("%s: %v\n%s", name, err, raw)
		}
	}
}

func TestSecretProbeNeverLeaksInAnyFormat(t *testing.T) {
	const probe = "adversarial-runtime-secret-value-zz99"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if !hasID(r, CHK01) {
		t.Fatalf("expected CHK01 for inline secret, got %+v", r.Findings)
	}
	human := Human(r)
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	blob := human + string(js) + string(sarif)
	if strings.Contains(blob, probe) {
		t.Fatal("probe leaked in check output")
	}
	for _, frag := range SecretFragments(r) {
		if strings.Contains(human, frag) || strings.Contains(string(js), frag) || strings.Contains(string(sarif), frag) {
			t.Fatalf("secret fragment leaked: %s", frag)
		}
	}
}

func TestSecretFragmentsIgnoreSyntheticMarkerInMessage(t *testing.T) {
	r := Result{Findings: []Finding{{
		ID:       CHK04,
		Severity: SevError,
		Target:   "web",
		Kind:     "service",
		Message:  "depends_on target synthetic-worker is not defined",
	}}}
	if frags := SecretFragments(r); len(frags) != 0 {
		t.Fatalf("plain message became Guard material: %v", frags)
	}
	genuine := Result{Findings: []Finding{{
		ID:      CHK01,
		Message: "value ghp_ComposeLensCheckProbe9999 quoted",
	}}}
	if frags := SecretFragments(genuine); len(frags) == 0 {
		t.Fatal("secret-shaped message must stay Guard material")
	}
}

func TestSecretFragmentsSkipIdentityTarget(t *testing.T) {
	const probe = "AKIAIOSFODNN7EXAMPLE"
	const name = "svc-javascript:alert(1)"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  \"" + name + "\":\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if !hasID(r, CHK01) {
		t.Fatalf("expected CHK01, got %+v", r.Findings)
	}
	for _, frag := range SecretFragments(r) {
		if strings.Contains(frag, name) {
			t.Fatalf("finding identity in Guard material: %q", frag)
		}
	}
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), name) && strings.Contains(string(js), probe) {
		t.Fatal("probe leaked beside identity")
	}
	if strings.Contains(string(js), probe) {
		t.Fatal("probe leaked in check JSON")
	}
}

func TestHumanShowsDigitServiceIdentityTargets(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  my-application-service-v2:\n    image: ${MISSING:?need}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if !hasID(r, CHK02) {
		t.Fatalf("expected CHK02, got %+v", r.Findings)
	}
	human := Human(r)
	if !strings.Contains(human, "services.my-application-service-v2.image") {
		t.Fatalf("human missing identity:\n%s", human)
	}
	if strings.Contains(human, "[redacted]") {
		t.Fatalf("human over-redacted identity:\n%s", human)
	}
}

func TestCHK01SkipsInterpolatedSecret(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${TOKEN}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, []string{"TOKEN=from-shell"}))
	if hasID(r, CHK01) {
		t.Fatalf("CHK01 false-fired on interpolated secret: %+v", r.Findings)
	}
}

func TestCHK01FixtureInlineDefault(t *testing.T) {
	r := Evaluate(fixture(t, "inline-default"))
	if !chk01Target(r, "web:DIRECT_SECRET") || !chk01Target(r, "web:DEFAULT_SECRET") {
		t.Fatalf("fixture inline-default %+v", r.Findings)
	}
	if chk01Count(r) != 2 {
		t.Fatalf("fixture want 2 CHK01 got %d %+v", chk01Count(r), r.Findings)
	}
}

func TestCHK01InterpolationDefaultFires(t *testing.T) {
	direct := "ghp_direct0000111122223333444455556"
	hidden := "ghp_hidden0000111122223333444455"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      DIRECT_SECRET: " + direct + "\n      DEFAULT_SECRET: ${UNSET_VAR:-" + hidden + "}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if !chk01Target(r, "web:DIRECT_SECRET") || !chk01Target(r, "web:DEFAULT_SECRET") {
		t.Fatalf("want both CHK01 targets, got %+v", r.Findings)
	}
	if chk01Count(r) != 2 {
		t.Fatalf("want total 2 CHK01, got %d %+v", chk01Count(r), r.Findings)
	}
	assertCHK01Withholds(t, r, direct, hidden)
}

func TestCHK01ExternalRefDoesNotFire(t *testing.T) {
	probe := "ghp_external0000111122223333444455"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      SECRET_ENV: ${SECRET_ENV}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, []string{"SECRET_ENV=" + probe}))
	if hasID(r, CHK01) {
		t.Fatalf("external ${SECRET_ENV} must not fire CHK01: %+v", r.Findings)
	}
}

func TestCHK01NonSecretDefaultDoesNotFire(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      COLOR: ${UNSET_VAR:-plain}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if hasID(r, CHK01) {
		t.Fatalf("non-secret default must not fire: %+v", r.Findings)
	}
}

func TestCHK01WinningOverlayLiteralFires(t *testing.T) {
	probe := "ghp_overlay000011112222333344445555"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${TOKEN}\n",
		"overlay.yaml": "services:\n  web:\n    environment:\n      API_TOKEN: " + probe + "\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml", "overlay.yaml"}, nil, []string{"TOKEN=from-shell"}))
	if !chk01Target(r, "web:API_TOKEN") {
		t.Fatalf("winning overlay literal must fire CHK01: %+v", r.Findings)
	}
	assertCHK01Withholds(t, r, probe)
}

func TestCHK01WinningOverlayExternalDoesNotFire(t *testing.T) {
	probe := "ghp_base000011112222333344445555678"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n",
		"overlay.yaml": "services:\n  web:\n    environment:\n      API_TOKEN: ${TOKEN}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml", "overlay.yaml"}, nil, []string{"TOKEN=from-shell"}))
	if hasID(r, CHK01) {
		t.Fatalf("winning overlay ${TOKEN} must not fire (secret not effective): %+v", r.Findings)
	}
}

func TestCHK01OverriddenHardcodedDefaultDoesNotFire(t *testing.T) {
	hidden := "ghp_unused00001111222233334444555"
	dir := writeTree(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${SET_VAR:-" + hidden + "}\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, []string{"SET_VAR=from-env"}))
	if hasID(r, CHK01) {
		t.Fatalf("unused secret default is not the effective value: %+v", r.Findings)
	}
}

func chk01Target(r Result, target string) bool {
	for _, f := range r.Findings {
		if f.ID == CHK01 && f.Target == target {
			return true
		}
	}
	return false
}

func chk01Count(r Result) int {
	n := 0
	for _, f := range r.Findings {
		if f.ID == CHK01 {
			n++
		}
	}
	return n
}

func assertCHK01Withholds(t *testing.T, r Result, probes ...string) {
	t.Helper()
	human := Human(r)
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	blob := human + string(js) + string(sarif)
	for _, p := range probes {
		if p != "" && strings.Contains(blob, p) {
			t.Fatalf("CHK01 echoed secret")
		}
	}
}

func TestCHK01AndCHK05TogetherHumanWithholdsSecret(t *testing.T) {
	const probe = "ghp_ComposeLensProfileProbe99"
	dir := writeTree(t, map[string]string{
		"shadow.env":   "COLOR=from-envfile\n",
		"compose.yaml": "services:\n  web:\n    image: webimg\n    env_file:\n      - shadow.env\n    environment:\n      - COLOR=from-environment\n      - API_TOKEN=" + probe + "\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml"}, nil, nil))
	if !hasID(r, CHK01) || !hasID(r, CHK05) {
		t.Fatalf("want CHK01+CHK05, got %+v", r.Findings)
	}
	human := Human(r)
	if strings.Contains(human, probe) {
		t.Fatalf("human contains probe:\n%s", human)
	}
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	sarif, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(js), probe) || strings.Contains(string(sarif), probe) {
		t.Fatal("json/sarif contain probe")
	}
	if !strings.Contains(human, "CHK01") || !strings.Contains(human, "CHK05") {
		t.Fatalf("human missing findings:\n%s", human)
	}
	if !strings.Contains(string(js), "compose.yaml") {
		t.Fatalf("json provenance should still include the path: %s", js)
	}
}

func TestHumanShowsFilesystemPathProvenanceJSONUnchanged(t *testing.T) {
	path := `winner:environment:C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\compose.yaml`
	r := Result{Findings: []Finding{{
		ID: CHK05, Severity: SevInfo, Target: "web:COLOR", Kind: "env",
		Message:    "container-environment variable is set by multiple sources; a lower-precedence source was overridden",
		Provenance: []string{path},
	}}}
	human := Human(r)
	if !strings.Contains(human, `C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\compose.yaml`) {
		t.Fatalf("human should show real filesystem path:\n%s", human)
	}
	if strings.Contains(human, "[redacted]") {
		t.Fatalf("human over-redacted a filesystem path:\n%s", human)
	}
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), "abcdefghijklmnop1234567890") {
		t.Fatalf("json must keep provenance unchanged: %s", js)
	}
}

func TestPositiveFixturesDoNotFalseFireOtherChecks(t *testing.T) {
	cases := []struct {
		name string
		only string
	}{
		{"secret-inline", CHK01},
		{"required-unset", CHK02},
		{"profiled-dep", CHK03},
		{"missing-include", CHK04},
		{"missing-extends", CHK04},
		{"env-shadowing", CHK05},
	}
	for _, tc := range cases {
		got := ids(Evaluate(fixture(t, tc.name)))
		if len(got) != 1 || got[0] != tc.only {
			t.Fatalf("%s: want only %s, got %v", tc.name, tc.only, got)
		}
	}
}

func TestSARIFPhysicalLocationSingleFileMatchesSource(t *testing.T) {
	in := fixture(t, "secret-inline")
	r := Evaluate(in)
	if chk01Count(r) != 1 {
		t.Fatalf("want 1 CHK01: %+v", r.Findings)
	}
	wantLine := 0
	wantFile := ""
	for _, se := range in.Container {
		for _, v := range se.Vars {
			if v.Key == "API_TOKEN" {
				wantLine = v.Winner.Line
				wantFile = v.Winner.Path
			}
		}
	}
	if wantLine < 1 || wantFile == "" {
		t.Fatalf("containerenv winner location missing")
	}
	uri, line, hasRegion, logical := sarifPhysical(t, r, "web:API_TOKEN")
	if uri != "compose.yaml" {
		t.Fatalf("uri=%q", uri)
	}
	if !hasRegion || line != wantLine || line != r.Findings[0].Line {
		t.Fatalf("startLine=%d want %d finding=%d", line, wantLine, r.Findings[0].Line)
	}
	if logical != "web:API_TOKEN" {
		t.Fatalf("logical=%q", logical)
	}
	if filepath.Base(wantFile) != "compose.yaml" {
		t.Fatalf("winner file %q", wantFile)
	}
	assertJSONHumanOmitPhysical(t, r)
}

func TestSARIFPhysicalLocationMatchesInterpInspectLine(t *testing.T) {
	in := fixture(t, "required-unset")
	r := Evaluate(in)
	if !hasID(r, CHK02) {
		t.Fatalf("%+v", r.Findings)
	}
	var locFile string
	var locLine int
	for _, v := range in.Interp {
		if v.State == interp.StateRequiredError {
			locFile = v.Location.File
			locLine = v.Location.Line
			break
		}
	}
	if locLine < 1 {
		t.Fatalf("interp location missing")
	}
	uri, line, hasRegion, logical := sarifPhysical(t, r, r.Findings[0].Target)
	if uri != "compose.yaml" || filepath.Base(locFile) != "compose.yaml" {
		t.Fatalf("uri=%q interp=%q", uri, locFile)
	}
	if !hasRegion || line != locLine {
		t.Fatalf("startLine=%d interp Line=%d (inspect File:Line)", line, locLine)
	}
	if logical != r.Findings[0].Target {
		t.Fatalf("logical=%q", logical)
	}
}

func TestSARIFPhysicalLocationWinningOverlay(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "overlay-win")
	in := snapshot(t, dir, []string{"compose.yaml", "overlay.yaml"}, nil, nil)
	r := Evaluate(in)
	if !chk01Target(r, "web:API_TOKEN") {
		t.Fatalf("%+v", r.Findings)
	}
	uri, line, hasRegion, _ := sarifPhysical(t, r, "web:API_TOKEN")
	if uri != "overlay.yaml" {
		t.Fatalf("winning file uri=%q", uri)
	}
	if !hasRegion || line < 1 {
		t.Fatalf("missing startLine")
	}
	var interpLine int
	for _, v := range in.Interp {
		if strings.Contains(v.Location.File, "overlay.yaml") && strings.Contains(v.Path, "API_TOKEN") {
			interpLine = v.Location.Line
			break
		}
	}
	if interpLine > 0 && line != interpLine {
		t.Fatalf("sarif line %d interp %d", line, interpLine)
	}
}

func TestSARIFPhysicalLocationNestedWinningOverlay(t *testing.T) {
	dir := writeTree(t, map[string]string{
		"compose.yaml":     "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${TOKEN}\n",
		"svc/overlay.yaml": "services:\n  web:\n    environment:\n      API_TOKEN: demo-overlay\n",
	})
	r := Evaluate(snapshot(t, dir, []string{"compose.yaml", "svc/overlay.yaml"}, nil, nil))
	uri, _, hasRegion, _ := sarifPhysical(t, r, "web:API_TOKEN")
	if uri != "svc/overlay.yaml" {
		t.Fatalf("nested uri=%q", uri)
	}
	if strings.Contains(uri, `\`) || uriLooksAbsolute(uri) {
		t.Fatalf("not portable: %q", uri)
	}
	if !hasRegion {
		t.Fatal("want startLine")
	}
}

func TestSARIFPhysicalLocationDegradesWithoutLine(t *testing.T) {
	r := Evaluate(fixture(t, "missing-include"))
	if !hasID(r, CHK04) {
		t.Fatalf("%+v", r.Findings)
	}
	uri, _, hasRegion, logical := sarifPhysical(t, r, r.Findings[0].Target)
	if uri != "compose.yaml" {
		t.Fatalf("uri=%q", uri)
	}
	if hasRegion {
		t.Fatal("absent include has no precise line; region must be omitted")
	}
	if logical == "" {
		t.Fatal("logicalLocations required")
	}
}

func TestSARIFFindingSetUnchangedJSONHuman(t *testing.T) {
	for _, name := range []string{"secret-inline", "inline-default", "required-unset", "profiled-dep", "missing-include", "env-shadowing"} {
		r := Evaluate(fixture(t, name))
		js, err := JSON(r)
		if err != nil {
			t.Fatal(err)
		}
		sarif, err := SARIF(r)
		if err != nil {
			t.Fatal(err)
		}
		jf, err := FingerprintsFromJSON(js)
		if err != nil {
			t.Fatal(err)
		}
		sf, err := FingerprintsFromSARIF(sarif)
		if err != nil {
			t.Fatal(err)
		}
		sort.Strings(jf)
		sort.Strings(sf)
		want := Fingerprints(r)
		if strings.Join(jf, ";") != strings.Join(want, ";") || strings.Join(sf, ";") != strings.Join(want, ";") {
			t.Fatalf("%s fingerprints json=%v sarif=%v want=%v", name, jf, sf, want)
		}
		assertJSONHumanOmitPhysical(t, r)
		raw := string(sarif)
		if strings.Contains(raw, `\`) || strings.Contains(strings.ToLower(raw), "file://") {
			t.Fatalf("%s sarif has absolute/file uri:\n%s", name, raw)
		}
	}
}

func sarifPhysical(t *testing.T, r Result, target string) (uri string, line int, hasRegion bool, logical string) {
	t.Helper()
	raw, err := SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	if len(log.Runs) != 1 {
		t.Fatalf("runs=%d", len(log.Runs))
	}
	for _, res := range log.Runs[0].Results {
		if len(res.Locations) == 0 {
			continue
		}
		loc := res.Locations[0]
		name := ""
		if len(loc.LogicalLocations) > 0 {
			name = loc.LogicalLocations[0].FullyQualifiedName
		}
		if name != target {
			continue
		}
		if loc.PhysicalLocation == nil {
			t.Fatalf("missing physicalLocation for %s", target)
		}
		uri = loc.PhysicalLocation.ArtifactLocation.URI
		if loc.PhysicalLocation.Region != nil {
			hasRegion = true
			line = loc.PhysicalLocation.Region.StartLine
		}
		return uri, line, hasRegion, name
	}
	t.Fatalf("no result for %s", target)
	return "", 0, false, ""
}

func assertJSONHumanOmitPhysical(t *testing.T, r Result) {
	t.Helper()
	human := Human(r)
	js, err := JSON(r)
	if err != nil {
		t.Fatal(err)
	}
	blob := human + string(js)
	for _, needle := range []string{"physicalLocation", "artifactLocation", "startLine"} {
		if strings.Contains(blob, needle) {
			t.Fatalf("human/JSON must not gain SARIF location keys (%s)", needle)
		}
	}
}
