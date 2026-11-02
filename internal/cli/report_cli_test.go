// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/check"
	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/report"
	"composelens/internal/safety"
)

func reportRT(dir string) (Runtime, *bytes.Buffer, *bytes.Buffer) {
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info {
		return engine.Info{State: evidence.Absent}
	}}
	return rt, &out, &errb
}

func TestReportHumanReserved(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--project-directory", dir})
	if code != exitcode.Unsupported {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(strings.ToLower(blob), "<html") || strings.Contains(strings.ToLower(blob), "<script") || strings.Contains(blob, "<!DOCTYPE") {
		t.Fatal("human report must not emit HTML")
	}
	if !strings.Contains(errb.String(), "report without --json or --html is not available in") {
		t.Fatalf("err=%s", errb.String())
	}
}

func TestReportJSONAndSARIFUsage(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--sarif", "--project-directory", dir})
	if code != exitcode.Usage {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
}

func TestReportJSONValidatesAndFidelity(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "required-unset")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("report code=%d err=%s", code, errb.String())
	}
	if err := report.ValidateBytes(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	var pkg report.Package
	if err := json.Unmarshal(out.Bytes(), &pkg); err != nil {
		t.Fatal(err)
	}
	if pkg.Schema != report.Schema || pkg.Determinism != report.Determinism {
		t.Fatalf("schema=%s det=%s", pkg.Schema, pkg.Determinism)
	}
	if pkg.Graph.Schema != "composelens.graph.v0" || pkg.Check.Schema != check.Schema {
		t.Fatalf("nested schema graph=%s check=%s", pkg.Graph.Schema, pkg.Check.Schema)
	}
	if pkg.Check.AssertionExit != exitcode.Assertion {
		t.Fatalf("assertionExit=%d", pkg.Check.AssertionExit)
	}
	if len(pkg.Diagnostics) == 0 || pkg.Diagnostics[0].Code != "exit.assertion" {
		t.Fatalf("diagnostics=%+v", pkg.Diagnostics)
	}
	foundWeb := false
	for _, s := range pkg.Source.Services {
		if s.Name == "web" && s.Identity == "services.web" {
			foundWeb = true
		}
	}
	if !foundWeb {
		t.Fatalf("services=%+v", pkg.Source.Services)
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"inspect", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("inspect code=%d err=%s", code, errb.String())
	}
	var insp inspectReport
	if err := json.Unmarshal(out.Bytes(), &insp); err != nil {
		t.Fatal(err)
	}
	if len(insp.Services) != len(pkg.Source.Services) {
		t.Fatalf("service count inspect=%d report=%d", len(insp.Services), len(pkg.Source.Services))
	}
	for i, s := range insp.Services {
		if s.Name != pkg.Source.Services[i].Name {
			t.Fatalf("service[%d] inspect=%s report=%s", i, s.Name, pkg.Source.Services[i].Name)
		}
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("explain --all code=%d err=%s", code, errb.String())
	}
	var graph struct {
		Schema string `json:"schema"`
		Counts struct {
			Total int `json:"total"`
		} `json:"counts"`
		Nodes []struct {
			Target string `json:"target"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	if graph.Schema != pkg.Graph.Schema || graph.Counts.Total != pkg.Graph.Counts.Total || len(graph.Nodes) != len(pkg.Graph.Nodes) {
		t.Fatalf("graph mismatch explain=%d/%s report=%d/%s", graph.Counts.Total, graph.Schema, pkg.Graph.Counts.Total, pkg.Graph.Schema)
	}
	for i, n := range graph.Nodes {
		if n.Target != pkg.Graph.Nodes[i].Target {
			t.Fatalf("graph node[%d] explain=%s report=%s", i, n.Target, pkg.Graph.Nodes[i].Target)
		}
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"check", "--json", "--project-directory", dir})
	if code != exitcode.Assertion {
		t.Fatalf("check code=%d err=%s", code, errb.String())
	}
	var chk check.Report
	if err := json.Unmarshal(out.Bytes(), &chk); err != nil {
		t.Fatal(err)
	}
	if len(chk.Findings) != len(pkg.Check.Findings) {
		t.Fatalf("findings check=%d report=%d", len(chk.Findings), len(pkg.Check.Findings))
	}
	for i, f := range chk.Findings {
		g := pkg.Check.Findings[i]
		if f.ID != g.ID || f.Target != g.Target || f.Severity != g.Severity || f.Waived != g.Waived {
			t.Fatalf("finding[%d] check=%+v report=%+v", i, f, g)
		}
	}
	if chk.Code != "" && (len(pkg.Diagnostics) == 0 || pkg.Diagnostics[0].Code != chk.Code) {
		t.Fatalf("diagnostic code check=%s report=%v", chk.Code, pkg.Diagnostics)
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"differential", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("differential code=%d err=%s", code, errb.String())
	}
	var diffDoc struct {
		Schema      string `json:"schema"`
		EngineState string `json:"engineState"`
		Summary     struct {
			Match        int `json:"match"`
			Divergent    int `json:"divergent"`
			OnlyInternal int `json:"onlyInternal"`
			OnlyEngine   int `json:"onlyEngine"`
			Uncertain    int `json:"uncertain"`
		} `json:"summary"`
	}
	if err := json.Unmarshal(out.Bytes(), &diffDoc); err != nil {
		t.Fatal(err)
	}
	if diffDoc.Schema != pkg.Differential.Schema || diffDoc.EngineState != pkg.Differential.EngineState {
		t.Fatalf("differential schema/state mismatch")
	}
	if diffDoc.Summary.Match != pkg.Differential.Summary.Match ||
		diffDoc.Summary.Divergent != pkg.Differential.Summary.Divergent ||
		diffDoc.Summary.OnlyInternal != pkg.Differential.Summary.OnlyInternal ||
		diffDoc.Summary.OnlyEngine != pkg.Differential.Summary.OnlyEngine ||
		diffDoc.Summary.Uncertain != pkg.Differential.Summary.Uncertain {
		t.Fatalf("differential summary mismatch cmd=%+v report=%+v", diffDoc.Summary, pkg.Differential.Summary)
	}
}

func TestReportDeterministic(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("first code=%d err=%s", code, errb.String())
	}
	first := append([]byte(nil), out.Bytes()...)
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("second code=%d err=%s", code, errb.String())
	}
	if !bytes.Equal(first, out.Bytes()) {
		t.Fatal("report --json not byte-identical across runs")
	}
}

func TestReportSecretSafeAndRedactConfig(t *testing.T) {
	dir := overlayProject(t)
	add := overlayWrite(t, dir, "add.yaml", `schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"
`)
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--redact", add, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	blob := out.String()
	if strings.Contains(blob, overlayCustom) || strings.Contains(blob, "keyed-secret-value") {
		t.Fatal("raw secret leaked in report package")
	}
	if strings.Contains(strings.ToLower(blob), "<html") || strings.Contains(blob, "<script") {
		t.Fatal("report --json emitted HTML")
	}
	if err := report.ValidateBytes(out.Bytes()); err != nil {
		t.Fatal(err)
	}
}

func TestReportBoundedOversizedInput(t *testing.T) {
	dir := t.TempDir()
	body := append([]byte("services:\n  web:\n    image: alpine\n"), bytes.Repeat([]byte("#"), int(safety.MaxFileBytes)+1)...)
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), body, 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout must stay empty: %s", out.String())
	}
	if !strings.Contains(errb.String(), "safety.input-too-large") && !strings.Contains(errb.String(), string(safety.CodeFileTooLarge)) {
		t.Fatalf("stderr=%s", errb.String())
	}
}

func TestDoctorListsReportDataPackage(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	rt, out, errb := reportRT(dir)
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	seenPkg, seenHTML, seenViews, seenA11y, seenCSP := false, false, false, false, false
	for _, f := range rep.Features.Implemented {
		if f == "report-data-package" {
			seenPkg = true
		}
		if f == "static-html-report" {
			seenHTML = true
		}
		if f == "interactive-html-report" {
			seenViews = true
		}
		if f == "accessible-html-report" {
			seenA11y = true
		}
		if f == "html-report-csp" {
			seenCSP = true
		}
	}
	if !seenPkg || !seenHTML || !seenViews || !seenA11y || !seenCSP {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "static-html-report" || f == "interactive-html-report" || f == "accessible-html-report" || f == "html-report-csp" {
			t.Fatalf("%s still deferred", f)
		}
	}
}

func TestReportHTMLOfflineAndJSONUnchanged(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("json code=%d err=%s", code, errb.String())
	}
	jsonA := append([]byte(nil), out.Bytes()...)
	if err := report.ValidateBytes(jsonA); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("html code=%d err=%s", code, errb.String())
	}
	page := out.Bytes()
	if refs := report.RemoteRefs(page); len(refs) > 0 {
		t.Fatalf("remote refs: %v", refs)
	}
	if !bytes.Contains(page, []byte("<!DOCTYPE html>")) || bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
		t.Fatal("expected self-contained shell without innerHTML")
	}
	island, err := report.DataIslandJSON(page)
	if err != nil {
		t.Fatal(err)
	}
	if err := report.ValidateBytes(island); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("json2 code=%d err=%s", code, errb.String())
	}
	if !bytes.Equal(jsonA, out.Bytes()) {
		t.Fatal("report --json changed after --html")
	}
}

func TestReportHTMLKeyboardViews(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "required-unset")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("html code=%d err=%s", code, errb.String())
	}
	page := out.Bytes()
	if refs := report.RemoteRefs(page); len(refs) > 0 {
		t.Fatalf("remote refs: %v", refs)
	}
	for _, s := range []string{
		`role="tablist"`,
		`data-view="graph"`,
		`data-view="source"`,
		`data-view="diff"`,
		`data-view="diagnostics"`,
		"ArrowDown",
		"Escape",
		`addEventListener("keydown"`,
		`:focus`,
		`id="skip-to-content"`,
		`aria-live="polite"`,
		`prefers-reduced-motion: reduce`,
		`lang="en"`,
		`Content-Security-Policy`,
		`default-src 'none'`,
		`href="#main"`,
	} {
		if !bytes.Contains(page, []byte(s)) {
			t.Fatalf("missing %q", s)
		}
	}
	if bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
		t.Fatal("innerHTML")
	}
}

func TestReportHTMLInertCLI(t *testing.T) {
	dir := t.TempDir()
	body := "" +
		"services:\n" +
		"  web:\n" +
		"    image: '</script><script>alert(1)</script>'\n" +
		"    environment:\n" +
		"      NOTE: '\"><img onerror=alert(1)>'\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	page := out.Bytes()
	if bytes.Contains(page, []byte("<script>alert")) || bytes.Contains(page, []byte("<img")) {
		t.Fatal("script-shaped compose values escaped into executable markup")
	}
	if bytes.Contains(page, []byte("</script><script>")) {
		t.Fatal("script breakout")
	}
	island, err := report.DataIslandJSON(page)
	if err != nil {
		t.Fatal(err)
	}
	var pkg report.Package
	if err := json.Unmarshal(island, &pkg); err != nil {
		t.Fatal(err)
	}
	gotScript, gotImg := false, false
	for _, n := range pkg.Graph.Nodes {
		if n.Effective == nil {
			continue
		}
		if *n.Effective == `</script><script>alert(1)</script>` {
			gotScript = true
		}
		if *n.Effective == `"><img onerror=alert(1)>` {
			gotImg = true
		}
	}
	if !gotScript || !gotImg {
		t.Fatalf("decoded island missing inert payloads script=%v img=%v", gotScript, gotImg)
	}
}

func TestReportHTMLHostileSchemesCLI(t *testing.T) {
	dir := t.TempDir()
	body := "" +
		"services:\n" +
		"  web:\n" +
		"    image: 'javascript:alert(1)'\n" +
		"    environment:\n" +
		"      NOTE: 'data:text/html,<script>alert(1)</script>'\n" +
		"    labels:\n" +
		"      x: 'vbscript:msgbox(1)'\n" +
		"    volumes:\n" +
		"      - '//evil.example/x:/data'\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	page := out.Bytes()
	if sinks := report.LiveSinks(page); len(sinks) > 0 {
		t.Fatalf("sinks: %v", sinks)
	}
	if bytes.Contains(page, []byte(`href="javascript:`)) || bytes.Contains(page, []byte(`src="javascript:`)) {
		t.Fatal("javascript: sink")
	}
	if bytes.Count(page, []byte("</script>")) != report.LegitScriptCloseCount {
		t.Fatalf("</script> count=%d", bytes.Count(page, []byte("</script>")))
	}
}

func TestReportHTMLDeterministicAndSecretSafe(t *testing.T) {
	dir := overlayProject(t)
	add := overlayWrite(t, dir, "add.yaml", `schema: composelens.redact.v0
secretKeys:
  - X_INTERNAL_ID
secretValues:
  - "^clx_[A-Za-z0-9]{24,}$"
`)
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--html", "--redact", add, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("first code=%d err=%s", code, errb.String())
	}
	first := append([]byte(nil), out.Bytes()...)
	if strings.Contains(string(first), overlayCustom) || strings.Contains(string(first), "keyed-secret-value") {
		t.Fatal("raw secret leaked in HTML")
	}
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"report", "--html", "--redact", add, "--project-directory", dir})
	if code != 0 {
		t.Fatalf("second code=%d err=%s", code, errb.String())
	}
	if !bytes.Equal(first, out.Bytes()) {
		t.Fatal("report --html not byte-identical")
	}
}

func TestReportJSONAndHTMLUsage(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--json", "--html", "--project-directory", dir})
	if code != exitcode.Usage {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
}
