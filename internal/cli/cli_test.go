// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"composelens/internal/check"
	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/redact"
)

var errNoEntropy = errors.New("fingerprint key generation failed")

func TestParseArgsRepeatableFlags(t *testing.T) {
	opt, err := ParseArgs([]string{"--json", "inspect", "-f", "a.yml", "--file", "b.yml", "--env-file", "e.env", "--profile", "debug", "--profile", "tools", "--project-directory", "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if !opt.JSON || opt.Command != "inspect" || len(opt.Files) != 2 || opt.Files[0] != "a.yml" || opt.EnvFiles[0] != "e.env" || opt.ProjectDirectory != "proj" || len(opt.Profiles) != 2 || opt.Profiles[0] != "debug" || opt.Profiles[1] != "tools" {
		t.Fatalf("%+v", opt)
	}
}

func TestVersionJSON(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"version", "--json"}, &out, &errb, nil)
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep versionReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != "composelens.version.v0" || rep.Name != "composelens" || rep.Version != "0.1.0" {
		t.Fatalf("%+v", rep)
	}
}

func TestExplainMissingTargetIsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"explain", "--json"}, &out, &errb, nil)
	if code != exitcode.Usage {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout=%s", out.String())
	}
	if !strings.Contains(errb.String(), "explain requires a target") {
		t.Fatalf("err=%s", errb.String())
	}
}

func TestParseArgsExplainAll(t *testing.T) {
	opt, err := ParseArgs([]string{"explain", "--all", "--json", "--project-directory", "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "explain" || !opt.All || !opt.JSON || opt.Target != "" {
		t.Fatalf("%+v", opt)
	}
}

func TestExplainAllJSONAndHuman(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "graph", "shadow-chain")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--all", "--json", "--env-file", "extra.env", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if string(m["schema"]) != `"composelens.graph.v0"` {
		t.Fatalf("schema %s", m["schema"])
	}
	if _, ok := m["nodes"]; !ok {
		t.Fatal("missing nodes")
	}
	if strings.Contains(out.String(), `"schema": "composelens.explain.v0"`) {
		t.Fatal("graph used explain schema")
	}
	blob := out.String()
	if !strings.Contains(blob, `"web:COLOR"`) || !strings.Contains(blob, `"worker"`) {
		t.Fatalf("whole-model missing: %s", blob)
	}
	if !strings.Contains(blob, `"shadowChain"`) {
		t.Fatal("missing shadowChain")
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"explain", "--all", "--env-file", "extra.env", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("human code=%d err=%s", code, errb.String())
	}
	h := out.String()
	if !strings.Contains(h, "provenance graph") || !strings.Contains(h, "web:COLOR") || !strings.Contains(h, "worker") {
		t.Fatalf("human %s", h)
	}
}

func TestExplainAllWithTargetIsUsage(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"explain", "--all", "web"}, &out, &errb, nil)
	if code != exitcode.Usage {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "--all cannot be combined with a target") {
		t.Fatalf("err=%s", errb.String())
	}
}

func TestAllOnlyValidWithExplain(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--all", "--project-directory", dir})
	if code != exitcode.Usage {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "--all is only valid with explain") {
		t.Fatalf("err=%s", errb.String())
	}
}

func TestExplainAllDoesNotChangeSingleTarget(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "interp-env")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"explain", "--json", "web:COLOR", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var exp explainReport
	if err := json.Unmarshal(out.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Schema != "composelens.explain.v0" || exp.Effective.Text == nil || *exp.Effective.Text != "teal" {
		t.Fatalf("%+v", exp)
	}
}

func TestExplainAllSecretProbe(t *testing.T) {
	dir := t.TempDir()
	const probe = "ghp_ComposeLensGraphProbe99"
	compose := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("json code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	if strings.Contains(out.String()+errb.String(), probe) {
		t.Fatal("raw secret leaked in graph json")
	}
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"explain", "--all", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("human code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	if strings.Contains(out.String()+errb.String(), probe) {
		t.Fatal("raw secret leaked in graph human")
	}
}

func TestDoctorListsGraphImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasGraph, hasShadow := false, false
	for _, f := range rep.Features.Implemented {
		if f == "provenance-graph" {
			hasGraph = true
		}
		if f == "shadow-chains" {
			hasShadow = true
		}
	}
	if !hasGraph || !hasShadow {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
}

func TestDoctorListsNormalizationImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasNorm := false
	for _, f := range rep.Features.Implemented {
		if f == "canonical-normalization" {
			hasNorm = true
		}
	}
	if !hasNorm {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "canonical-normalization" {
			t.Fatal("canonical-normalization still deferred")
		}
		if f == "compose-engine-differential" {
			t.Fatal("compose-engine-differential still deferred")
		}
	}
}

func TestDoctorListsFixtureTaxonomyImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasTax := false
	for _, f := range rep.Features.Implemented {
		if f == "fixture-taxonomy" {
			hasTax = true
		}
	}
	if !hasTax {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "fixture-taxonomy" {
			t.Fatal("fixture-taxonomy still deferred")
		}
		if f == "compose-engine-differential" {
			t.Fatal("compose-engine-differential still deferred")
		}
	}
}

func TestDoctorListsEngineAdapterImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasAdapter := false
	for _, f := range rep.Features.Implemented {
		if f == "compose-engine-adapter" {
			hasAdapter = true
		}
	}
	if !hasAdapter {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "compose-engine-adapter" {
			t.Fatal("compose-engine-adapter still deferred")
		}
		if f == "compose-engine-differential" {
			t.Fatal("compose-engine-differential still deferred")
		}
	}
}

func TestDoctorListsEngineCapabilityImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasCap := false
	for _, f := range rep.Features.Implemented {
		if f == "compose-engine-capability" {
			hasCap = true
		}
	}
	if !hasCap {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	if rep.EngineCapabilities.Support != "engine-absent" {
		t.Fatalf("capabilities support %s", rep.EngineCapabilities.Support)
	}
	for _, f := range rep.Features.Deferred {
		if f == "compose-engine-capability" {
			t.Fatal("compose-engine-capability still deferred")
		}
		if f == "compose-engine-differential" {
			t.Fatal("compose-engine-differential still deferred")
		}
	}
}

func TestDoctorJSONRecognizedFamily(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info {
		return engine.Info{State: evidence.Known, Version: "v5.4.0", Certainty: evidence.Proven}
	}}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.EngineCapabilities.Support != "recognized" {
		t.Fatalf("support %s want recognized", rep.EngineCapabilities.Support)
	}
	if strings.Contains(rep.EngineCapabilities.Support, "supported") {
		t.Fatal("bare supported")
	}
}

func TestDoctorListsDifferentialImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	has := false
	for _, f := range rep.Features.Implemented {
		if f == "compose-engine-differential" {
			has = true
		}
	}
	if !has {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "compose-engine-differential" {
			t.Fatal("compose-engine-differential still deferred")
		}
	}
}

func TestDifferentialSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"differential", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	if strings.Contains(out.String()+errb.String(), probe) {
		t.Fatal("raw secret leaked in differential JSON")
	}
	if !strings.Contains(out.String(), `"schema": "composelens.differential.v0"`) {
		t.Fatalf("out=%s", out.String())
	}
}

func TestUnsupportedReport(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"report", "--project-directory", dir})
	if code != exitcode.Unsupported {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "report without --json or --html is not available in") {
		t.Fatalf("err=%s", errb.String())
	}
}

func TestParseArgsCheckSARIF(t *testing.T) {
	opt, err := ParseArgs([]string{"check", "--sarif", "--project-directory", "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "check" || !opt.SARIF || opt.JSON {
		t.Fatalf("%+v", opt)
	}
}

func TestCheckJSONAndSARIFMutuallyExclusive(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--json", "--sarif", "--project-directory", dir})
	if code != exitcode.Usage {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
}

func TestParseArgsCheckGitHub(t *testing.T) {
	opt, err := ParseArgs([]string{"check", "--github", "--project-directory", "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "check" || !opt.GitHub || opt.JSON || opt.SARIF {
		t.Fatalf("%+v", opt)
	}
}

func TestCheckJSONAndGitHubMutuallyExclusive(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--json", "--github", "--project-directory", dir})
	if code != exitcode.Usage {
		t.Fatalf("code=%d out=%s err=%s", code, out.String(), errb.String())
	}
}

func TestCheckGitHubSecretInlineMatchesSARIFAndIsSecretSafe(t *testing.T) {
	clearGitHubEnv(t)
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	run := func(args []string) (int, string, string) {
		t.Helper()
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		code := rt.Run(args)
		return code, out.String(), errb.String()
	}
	code, sarifOut, errb := run([]string{"check", "--sarif", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("sarif code=%d err=%s", code, errb)
	}
	uri, line := sarifURILine(t, sarifOut, "web:API_TOKEN")
	if uri != "compose.yaml" || line < 1 {
		t.Fatalf("sarif loc %s:%d", uri, line)
	}
	tmp := t.TempDir()
	jsonPath := filepath.Join(tmp, "composelens-check.json")
	sarifPath := filepath.Join(tmp, "composelens-check.sarif")
	sumPath := filepath.Join(tmp, "composelens-check.md")
	t.Setenv("COMPOSELENS_JSON_PATH", jsonPath)
	t.Setenv("COMPOSELENS_SARIF_PATH", sarifPath)
	t.Setenv("COMPOSELENS_GITHUB_SUMMARY", sumPath)
	t.Setenv("COMPOSELENS_FAIL_ON", "error")
	code, ghOut, errb := run([]string{"check", "--github", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("github code=%d err=%s out=%s", code, errb, ghOut)
	}
	want := "::warning file=" + uri + ",line=" + strconv.Itoa(line) + "::"
	if !strings.Contains(ghOut, want) {
		t.Fatalf("annotation missing %q in %q", want, ghOut)
	}
	if strings.Contains(ghOut, `C:\`) || strings.Contains(ghOut, "/Users/") {
		t.Fatalf("absolute path in annotation: %s", ghOut)
	}
	blob := ghOut + errb
	sum, err := os.ReadFile(sumPath)
	if err != nil {
		t.Fatal(err)
	}
	js, err := os.ReadFile(jsonPath)
	if err != nil {
		t.Fatal(err)
	}
	savedSARIF, err := os.ReadFile(sarifPath)
	if err != nil {
		t.Fatal(err)
	}
	blob += string(sum) + string(js) + string(savedSARIF)
	if strings.Contains(blob, "demo-inline") {
		t.Fatal("demo-inline leaked in github adapters")
	}
	if !strings.Contains(string(sum), "composelens-check.json") || !strings.Contains(string(sum), "composelens-check.sarif") {
		t.Fatalf("summary missing artifact links:\n%s", sum)
	}
	if !strings.Contains(string(js), `"schema": "composelens.check.v0"`) {
		t.Fatalf("json=%s", js)
	}
	if err := check.ValidateSARIF(savedSARIF); err != nil {
		t.Fatal(err)
	}
}

func sarifURILine(t *testing.T, raw, target string) (string, int) {
	t.Helper()
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation *struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine int `json:"startLine"`
						} `json:"region"`
					} `json:"physicalLocation"`
					LogicalLocations []struct {
						FullyQualifiedName string `json:"fullyQualifiedName"`
					} `json:"logicalLocations"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal([]byte(raw), &log); err != nil {
		t.Fatal(err)
	}
	for _, run := range log.Runs {
		for _, res := range run.Results {
			for _, loc := range res.Locations {
				name := ""
				if len(loc.LogicalLocations) > 0 {
					name = loc.LogicalLocations[0].FullyQualifiedName
				}
				if name != target || loc.PhysicalLocation == nil {
					continue
				}
				line := 0
				if loc.PhysicalLocation.Region != nil {
					line = loc.PhysicalLocation.Region.StartLine
				}
				return loc.PhysicalLocation.ArtifactLocation.URI, line
			}
		}
	}
	t.Fatalf("no physicalLocation for %s", target)
	return "", 0
}

func TestCheckCLICleanZeroFindings(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.check.v0"`) || !strings.Contains(out.String(), `"total": 0`) {
		t.Fatalf("out=%s", out.String())
	}
}

func TestCheckCLIExitMatrixAndPolicyGate(t *testing.T) {
	clean := filepath.Join("..", "..", "fixtures", "check", "clean")
	secret := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	req := filepath.Join("..", "..", "fixtures", "check", "required-unset")
	run := func(dir string, args ...string) (int, string, string) {
		t.Helper()
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		code := rt.Run(args)
		return code, out.String(), errb.String()
	}
	code, _, errb := run(clean, "check", "--json", "--project-directory", clean)
	if code != 0 {
		t.Fatalf("clean: %d %s", code, errb)
	}
	code, js, errb := run(secret, "check", "--json", "--project-directory", secret)
	if code != 0 {
		t.Fatalf("warning-only: %d %s", code, errb)
	}
	if !strings.Contains(js, `"id": "CHK01"`) || !strings.Contains(js, `"severity": "warning"`) {
		t.Fatalf("findings drifted without policy: %s", js)
	}
	code, _, errb = run(req, "check", "--json", "--project-directory", req)
	if code != exitcode.Assertion {
		t.Fatalf("error finding: %d %s", code, errb)
	}
	polDir := t.TempDir()
	gateWarn := filepath.Join(polDir, "gate-warning.yaml")
	if err := os.WriteFile(gateWarn, []byte("schema: composelens.policy.v0\ngate: warning\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb = run(secret, "check", "--json", "--policy", gateWarn, "--project-directory", secret)
	if code != exitcode.Assertion {
		t.Fatalf("gate warning: %d %s", code, errb)
	}
	remap := filepath.Join(polDir, "chk01-error.yaml")
	if err := os.WriteFile(remap, []byte("schema: composelens.policy.v0\nrules:\n  - id: CHK01\n    severity: error\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, errb = run(secret, "check", "--json", "--policy", remap, "--project-directory", secret)
	if code != exitcode.Assertion {
		t.Fatalf("severity remap: %d %s", code, errb)
	}
}

func TestCheckCLIEachRuleAndFormatsAgree(t *testing.T) {
	cases := []struct {
		dir  string
		id   string
		exit int
	}{
		{"secret-inline", "CHK01", 0},
		{"required-unset", "CHK02", exitcode.Assertion},
		{"profiled-dep", "CHK03", 0},
		{"missing-include", "CHK04", exitcode.Assertion},
		{"env-shadowing", "CHK05", 0},
	}
	for _, tc := range cases {
		dir := filepath.Join("..", "..", "fixtures", "check", tc.dir)
		rtJSON := func() (int, string, string) {
			var out, errb bytes.Buffer
			rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
			code := rt.Run([]string{"check", "--json", "--project-directory", dir})
			return code, out.String(), errb.String()
		}
		code, js, errb := rtJSON()
		if code != tc.exit {
			t.Fatalf("%s json code=%d want %d err=%s", tc.dir, code, tc.exit, errb)
		}
		if !strings.Contains(js, `"id": "`+tc.id+`"`) {
			t.Fatalf("%s missing %s in %s", tc.dir, tc.id, js)
		}
		var outH, errH bytes.Buffer
		rtH := Runtime{Stdout: &outH, Stderr: &errH, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		if code := rtH.Run([]string{"check", "--project-directory", dir}); code != tc.exit {
			t.Fatalf("%s human code=%d want %d err=%s", tc.dir, code, tc.exit, errH.String())
		}
		if !strings.Contains(outH.String(), tc.id) {
			t.Fatalf("%s human missing %s: %s", tc.dir, tc.id, outH.String())
		}
		var outS, errS bytes.Buffer
		rtS := Runtime{Stdout: &outS, Stderr: &errS, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		if code := rtS.Run([]string{"check", "--sarif", "--project-directory", dir}); code != tc.exit {
			t.Fatalf("%s sarif code=%d want %d err=%s", tc.dir, code, tc.exit, errS.String())
		}
		if !strings.Contains(outS.String(), `"ruleId": "`+tc.id+`"`) || !strings.Contains(outS.String(), `"version": "2.1.0"`) {
			t.Fatalf("%s sarif=%s", tc.dir, outS.String())
		}
	}
}

func TestCheckCLISecretProbe(t *testing.T) {
	const probe = "ghp_ComposeLensProfileProbe99"
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"check", "--project-directory", dir},
		{"check", "--json", "--project-directory", dir},
		{"check", "--sarif", "--project-directory", dir},
		{"check", "--github", "--project-directory", dir},
	} {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		code := rt.Run(args)
		if code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, probe) {
			t.Fatalf("probe leaked for %v", args)
		}
	}
}

func TestCheckHumanSecretPlusEnvShadowDoesNotFailClosed(t *testing.T) {
	const probe = "ghp_ComposeLensProfileProbe99"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "shadow.env"), []byte("COLOR=from-envfile\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "services:\n  web:\n    image: webimg\n    env_file:\n      - shadow.env\n    environment:\n      - COLOR=from-environment\n      - API_TOKEN=" + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	run := func(args []string) (int, string, string) {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		code := rt.Run(args)
		return code, out.String(), errb.String()
	}
	hCode, hOut, hErr := run([]string{"check", "--project-directory", dir})
	if hCode != 0 {
		t.Fatalf("human code=%d out=%q err=%s", hCode, hOut, hErr)
	}
	if strings.Contains(hOut+hErr, probe) {
		t.Fatal("probe leaked in human")
	}
	if !strings.Contains(hOut, "CHK01") || !strings.Contains(hOut, "CHK05") {
		t.Fatalf("human missing findings: %s", hOut)
	}
	jCode, jOut, jErr := run([]string{"check", "--json", "--project-directory", dir})
	if jCode != 0 {
		t.Fatalf("json code=%d err=%s", jCode, jErr)
	}
	if strings.Contains(jOut+jErr, probe) {
		t.Fatal("probe leaked in json")
	}
	sCode, sOut, sErr := run([]string{"check", "--sarif", "--project-directory", dir})
	if sCode != 0 {
		t.Fatalf("sarif code=%d err=%s", sCode, sErr)
	}
	if strings.Contains(sOut+sErr, probe) {
		t.Fatal("probe leaked in sarif")
	}
	if !strings.Contains(jOut, `"id": "CHK01"`) || !strings.Contains(jOut, `"id": "CHK05"`) {
		t.Fatalf("json findings %s", jOut)
	}
	if !strings.Contains(sOut, `"ruleId": "CHK01"`) || !strings.Contains(sOut, `"ruleId": "CHK05"`) {
		t.Fatalf("sarif findings %s", sOut)
	}
}

func TestCheckDoesNotChangeInspectExplainOrDiff(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "interp-env")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var inspect map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &inspect); err != nil {
		t.Fatal(err)
	}
	if string(inspect["view"]) != `"source-level"` || string(inspect["schema"]) != `"composelens.inspect.v0"` {
		t.Fatalf("inspect %+v", inspect)
	}
	if _, ok := inspect["findings"]; ok {
		t.Fatal("inspect gained check findings")
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"explain", "--json", "web:COLOR", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var exp explainReport
	if err := json.Unmarshal(out.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Schema != "composelens.explain.v0" || exp.Effective.Text == nil || *exp.Effective.Text != "teal" {
		t.Fatalf("%+v", exp)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"diff", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.diff.v0"`) {
		t.Fatalf("diff %s", out.String())
	}
}

func TestDoctorListsCheckImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasCheck := false
	for _, f := range rep.Features.Implemented {
		if f == "check" {
			hasCheck = true
		}
	}
	if !hasCheck {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "check" {
			t.Fatal("check still deferred")
		}
	}
	hasPolicy, hasSarif := false, false
	for _, f := range rep.Features.Deferred {
		if f == "policy-engine" {
			hasPolicy = true
		}
		if f == "sarif-upload" {
			hasSarif = true
		}
		if f == "provenance-graph" || f == "shadow-chains" {
			t.Fatalf("graph still deferred %v", rep.Features.Deferred)
		}
	}
	if !hasPolicy || !hasSarif {
		t.Fatalf("deferred %v", rep.Features.Deferred)
	}
}

func TestParseArgsDiffSides(t *testing.T) {
	opt, err := ParseArgs([]string{"diff", "--json", "--left-profile", "a", "--right-profile", "b", "--left-env-file", "l.env", "--right-env-file", "r.env"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "diff" || !opt.JSON || len(opt.LeftProfiles) != 1 || opt.LeftProfiles[0] != "a" || opt.RightProfiles[0] != "b" || opt.LeftEnvFiles[0] != "l.env" || opt.RightEnvFiles[0] != "r.env" {
		t.Fatalf("%+v", opt)
	}
}

func TestDiffCLIIdenticalEmpty(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "diff", "profiles")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"diff", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep diffReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != "composelens.diff.v0" || !rep.Empty || len(rep.Changes) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestDiffCLIProfileEnablesService(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "diff", "profiles")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"diff", "--json", "--right-profile", "debug", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep diffReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range rep.Changes {
		if c.Kind == "service" && c.Target == "debug" && c.Change == "added" {
			found = true
			if c.Left.Present || !c.Right.Present {
				t.Fatalf("%+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("changes %+v", rep.Changes)
	}
}

func TestDiffCLIEnvSourceAndOneSideOnly(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "diff", "env-source")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"diff", "--json", "--left-env-file", "left.interp.env", "--right-env-file", "right.interp.env", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	var rep diffReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var color, onlyLeft bool
	for _, c := range rep.Changes {
		if c.Kind == "env" && c.Target == "web:COLOR" && c.Change == "changed" {
			color = true
			if c.Left.Value.Text == nil || *c.Left.Value.Text != "from-left" || c.Right.Value.Text == nil || *c.Right.Value.Text != "from-right" {
				t.Fatalf("color values %+v", c)
			}
			if c.Left.Source == c.Right.Source || !strings.Contains(c.Left.Source, "left.env") || !strings.Contains(c.Right.Source, "right.env") {
				t.Fatalf("color sources %+v", c)
			}
		}
		if c.Kind == "env" && c.Target == "web:ONLY_LEFT" && c.Change == "removed" {
			onlyLeft = true
		}
	}
	if !color || !onlyLeft {
		t.Fatalf("changes %+v", rep.Changes)
	}
}

func TestDiffCLISecretChangedByPresence(t *testing.T) {
	dir := t.TempDir()
	leftTok := "synthetic-merge-token-overlay"
	rightTok := "synthetic-merge-token-value"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: ${TOKEN}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "left.env"), []byte("TOKEN="+leftTok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "right.env"), []byte("TOKEN="+rightTok+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"diff", "--json", "--left-env-file", "left.env", "--right-env-file", "right.env", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(blob, leftTok) || strings.Contains(blob, rightTok) {
		t.Fatal("raw secret leaked in diff")
	}
	var rep diffReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, c := range rep.Changes {
		if c.Kind == "env" && c.Target == "web:API_TOKEN" {
			found = true
			if !c.Secret || c.Change != "changed" || !c.Left.Value.Redacted || !c.Right.Value.Redacted || c.Left.Value.Text != nil || c.Right.Value.Text != nil {
				t.Fatalf("%+v", c)
			}
		}
	}
	if !found {
		t.Fatalf("changes %+v", rep.Changes)
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"diff", "--left-env-file", "left.env", "--right-env-file", "right.env", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("human code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), leftTok) || strings.Contains(out.String()+errb.String(), rightTok) {
		t.Fatal("raw secret leaked in human diff")
	}
}

func TestDiffDoesNotChangeInspectOrExplain(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "interp-env")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var inspect map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &inspect); err != nil {
		t.Fatal(err)
	}
	if string(inspect["view"]) != `"source-level"` || string(inspect["schema"]) != `"composelens.inspect.v0"` {
		t.Fatalf("inspect %+v", inspect)
	}
	if _, ok := inspect["changes"]; ok {
		t.Fatal("inspect gained diff changes")
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"explain", "--json", "web:COLOR", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var exp explainReport
	if err := json.Unmarshal(out.Bytes(), &exp); err != nil {
		t.Fatal(err)
	}
	if exp.Schema != "composelens.explain.v0" || exp.Effective.Text == nil || *exp.Effective.Text != "teal" {
		t.Fatalf("%+v", exp)
	}
}

func TestDoctorListsDiffImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	hasDiff, hasExplain := false, false
	for _, f := range rep.Features.Implemented {
		if f == "diff" {
			hasDiff = true
		}
		if f == "explain" {
			hasExplain = true
		}
	}
	if !hasDiff || !hasExplain {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "diff" || f == "explain" {
			t.Fatalf("%s still deferred", f)
		}
	}
}

func TestParseArgsExplainTarget(t *testing.T) {
	opt, err := ParseArgs([]string{"explain", "--json", "web:COLOR", "-f", "compose.yaml"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "explain" || opt.Target != "web:COLOR" || !opt.JSON || len(opt.Files) != 1 {
		t.Fatalf("%+v", opt)
	}
}

func TestExplainCLIInterpAndContainerEnv(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "interp-env")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--json", "web:COLOR", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep explainReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != "composelens.explain.v0" || rep.State != "ok" || rep.FinalStage != "container-environment" {
		t.Fatalf("%+v", rep)
	}
	if rep.Effective.Text == nil || *rep.Effective.Text != "teal" {
		t.Fatalf("effective %+v", rep.Effective)
	}
	names := make([]string, 0, len(rep.Stages))
	for _, s := range rep.Stages {
		names = append(names, s.Name)
	}
	joined := strings.Join(names, ",")
	if !strings.Contains(joined, "interpolation") || !strings.Contains(joined, "container-environment") {
		t.Fatalf("stages %v", names)
	}
}

func TestExplainCLIExtendsThenMerge(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "extends-merge")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--json", "services.app.hostname", "-f", "compose.yaml", "-f", "overlay.yaml", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep explainReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.State != "ok" || rep.Effective.Text == nil || *rep.Effective.Text != "from-base" {
		t.Fatalf("%+v", rep)
	}
	var hasExtends, hasMerge bool
	for _, s := range rep.Stages {
		if s.Name == "extends" && s.Origin == "inherited" {
			hasExtends = true
		}
		if s.Name == "merge" {
			hasMerge = true
		}
	}
	if !hasExtends || !hasMerge {
		t.Fatalf("stages %+v", rep.Stages)
	}
}

func TestExplainCLIProfileDisabled(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "profiles")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--json", "debug", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep explainReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.State != "ok" || rep.FinalStage != "profiles" || len(rep.Stages) != 1 || rep.Stages[0].State != "disabled" {
		t.Fatalf("%+v", rep)
	}
	if !strings.Contains(rep.Stages[0].Reason, "disabled") && !strings.Contains(strings.ToLower(rep.Stages[0].Reason+rep.Effective.State), "disabled") {
		if rep.Effective.Text == nil || *rep.Effective.Text != "disabled" {
			t.Fatalf("not disabled %+v", rep)
		}
	}
}

func TestExplainCLISecretRedacted(t *testing.T) {
	dir := t.TempDir()
	secret := "synthetic-merge-token-overlay"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: "+secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--json", "web:API_TOKEN", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(blob, secret) {
		t.Fatal("raw secret leaked in explain")
	}
	var rep explainReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Secret || !rep.Effective.Redacted || rep.Effective.Text != nil {
		t.Fatalf("effective %+v", rep.Effective)
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"explain", "web:API_TOKEN", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("human code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), secret) {
		t.Fatal("raw secret leaked in human explain")
	}
}

func TestExplainCLIAbsentTarget(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "absent")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"explain", "--json", "missing", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep explainReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.State != "absent" || len(rep.Stages) != 0 {
		t.Fatalf("%+v", rep)
	}
}

func TestExplainDoesNotChangeInspectSchema(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "explain", "interp-env")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["stages"]; ok {
		t.Fatal("inspect gained explain stages")
	}
	if string(m["view"]) != `"source-level"` {
		t.Fatalf("view %s", m["view"])
	}
	if _, ok := m["containerEnvironment"]; !ok {
		t.Fatal("inspect lost containerEnvironment")
	}
	if _, ok := m["normalization"]; !ok {
		t.Fatal("inspect lost normalization")
	}
}

func TestDoctorListsExplainImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range rep.Features.Implemented {
		if f == "explain" {
			found = true
		}
	}
	if !found {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "explain" || f == "provenance-graph" || f == "shadow-chains" {
			t.Fatalf("still deferred %s in %v", f, rep.Features.Deferred)
		}
	}
}

func TestInspectSourceLevelAndRedaction(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:1.27-alpine\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "adversarial-runtime-secret-value-zz99"
	dotenv := "APP_ENV=dev\nAPI_TOKEN=" + secret + "\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotenv), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Environ: []string{"COMPOSE_PROJECT_NAME=lab"},
		Cwd:     dir,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent, Certainty: evidence.Proven} },
	}
	code := rt.Run([]string{"inspect", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("raw secret leaked in inspect JSON")
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.View != "source-level" || rep.Disclaimer != "source-level view — not resolved provenance" {
		t.Fatalf("view %+v", rep)
	}
	if len(rep.Services) != 1 || rep.Services[0].Name != "web" || rep.Services[0].Location.Line != 2 {
		t.Fatalf("services %+v", rep.Services)
	}
	foundToken := false
	for _, e := range rep.Environment {
		if e.Key == "API_TOKEN" {
			foundToken = true
			if !e.Secret || e.Evidence != evidence.Unresolved {
				t.Fatalf("token %+v", e)
			}
			if len(e.Sources) != 1 || !e.Sources[0].Value.Redacted || e.Sources[0].Value.Text != nil {
				t.Fatalf("token source %+v", e.Sources)
			}
		}
	}
	if !foundToken {
		t.Fatal("API_TOKEN missing")
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"doctor", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("doctor code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String(), secret) {
		t.Fatal("raw secret leaked in doctor JSON")
	}
}

func TestInspectCredentialURLsHumanAndJSON(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	dotenv := "" +
		"DATABASE_URL=postgres://demo-user:synthetic-password@db.internal/app\n" +
		"SAFE_URL=postgres://localhost:5432/app\n" +
		"HOOK=https://api.example.invalid/hook?token=synthetic-token-value\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotenv), 0o644); err != nil {
		t.Fatal(err)
	}
	dockerHost := "tcp://demo-user:synthetic-password@internal-host/socket"
	rt := Runtime{
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
		Cwd:     dir,
		Environ: []string{"DOCKER_HOST=" + dockerHost},
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	out := rt.Stdout.(*bytes.Buffer)
	errb := rt.Stderr.(*bytes.Buffer)
	secrets := []string{"synthetic-password", dockerHost, "postgres://demo-user:synthetic-password@db.internal/app", "synthetic-token-value"}
	for _, mode := range [][]string{
		{"inspect", "--project-directory", dir},
		{"inspect", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		code := rt.Run(mode)
		if code != 0 {
			t.Fatalf("%v code=%d err=%s", mode, code, errb.String())
		}
		blob := out.String() + errb.String()
		for _, s := range secrets {
			if strings.Contains(blob, s) {
				t.Fatalf("%v leaked %q", mode, s)
			}
		}
		if !strings.Contains(out.String(), "SAFE_URL") && !strings.Contains(out.String(), "postgres://localhost:5432/app") {
			t.Fatalf("safe URL missing from %v: %s", mode, out.String())
		}
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	saw := map[string]EnvKeyReport{}
	for _, e := range rep.Environment {
		saw[e.Key] = e
	}
	for _, k := range []string{"DOCKER_HOST", "DATABASE_URL", "HOOK"} {
		e, ok := saw[k]
		if !ok || !e.Secret || len(e.Sources) == 0 || !e.Sources[0].Value.Redacted || e.Sources[0].Value.Text != nil {
			t.Fatalf("%s not redacted: %+v", k, e)
		}
	}
	safe := saw["SAFE_URL"]
	if safe.Secret || len(safe.Sources) == 0 || safe.Sources[0].Value.Redacted || safe.Sources[0].Value.Text == nil || *safe.Sources[0].Value.Text != "postgres://localhost:5432/app" {
		t.Fatalf("SAFE_URL wrongly redacted: %+v", safe)
	}
}

func TestFingerprintRandFailureNoOutput(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout: &out,
		Stderr: &errb,
		Cwd:    dir,
		Detect: func() engine.Info { return engine.Info{State: evidence.Absent} },
		NewFingerprinter: func() (*redact.Fingerprinter, error) {
			return nil, errNoEntropy
		},
	}
	code := rt.Run([]string{"inspect", "--json"})
	if code != exitcode.Safety {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout not empty: %s", out.String())
	}
	if !strings.Contains(errb.String(), "fail-closed") {
		t.Fatalf("stderr=%s", errb.String())
	}
}

func TestInspectFingerprintsDifferAcrossRuns(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("APP_ENV=dev\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp := func() string {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		if code := rt.Run([]string{"inspect", "--json"}); code != 0 {
			t.Fatalf("err=%s", errb.String())
		}
		var rep inspectReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		for _, e := range rep.Environment {
			if e.Key == "APP_ENV" && len(e.Sources) > 0 {
				return e.Sources[0].Fingerprint
			}
		}
		t.Fatal("APP_ENV missing")
		return ""
	}
	a, b := fp(), fp()
	if a == "" || a == b {
		t.Fatalf("cross-run fingerprints linked: %s %s", a, b)
	}
}

func TestExplicitMissingFile(t *testing.T) {
	dir := t.TempDir()
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--file", filepath.Join(dir, "missing.yaml")})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
}

func TestInspectSensitiveQueryKeyFamily(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SAFE_URL=postgres://localhost:5432/app\nPAGE_URL=https://api.example.invalid/items?page=2&sort=name\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	access := "https://api.example.invalid/hook?access_token=synthetic-access-token-value"
	refresh := "https://api.example.invalid/hook?refresh_token=synthetic-refresh-token-value"
	auth := "https://api.example.invalid/hook?auth_token=synthetic-auth-token-value"
	client := "https://api.example.invalid/hook?client_secret=synthetic-client-secret-value"
	pwd := "https://api.example.invalid/hook?pwd=synthetic-pwd-value"
	hyphen := "https://api.example.invalid/hook?access-token=synthetic-hyphen-token-value"
	environ := []string{
		"DOCKER_HOST=" + access,
		"COMPOSE_PROJECT_NAME=lab",
	}
	dotenv := "REFRESH=" + refresh + "\nAUTH=" + auth + "\nCLIENT=" + client + "\nPWDURL=" + pwd + "\nHYPHEN=" + hyphen + "\nSAFE_URL=postgres://localhost:5432/app\nPAGE_URL=https://api.example.invalid/items?page=2&sort=name\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotenv), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := Runtime{
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
		Cwd:     dir,
		Environ: environ,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	out := rt.Stdout.(*bytes.Buffer)
	errb := rt.Stderr.(*bytes.Buffer)
	leaks := []string{"synthetic-access-token-value", "synthetic-refresh-token-value", "synthetic-auth-token-value", "synthetic-client-secret-value", "synthetic-pwd-value", "synthetic-hyphen-token-value"}
	for _, mode := range [][]string{
		{"inspect", "--project-directory", dir},
		{"inspect", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(mode); code != 0 {
			t.Fatalf("%v code=%d err=%s", mode, code, errb.String())
		}
		blob := out.String() + errb.String()
		for _, s := range leaks {
			if strings.Contains(blob, s) {
				t.Fatalf("%v leaked %s", mode, s)
			}
		}
		if !strings.Contains(out.String(), "postgres://localhost:5432/app") {
			t.Fatalf("safe URL missing: %s", out.String())
		}
		if !strings.Contains(out.String(), "page=2") || !strings.Contains(out.String(), "sort=name") {
			t.Fatalf("pagination missing: %s", out.String())
		}
	}
}

func TestEarlyErrorsDoNotEchoSecrets(t *testing.T) {
	cases := []struct {
		name string
		args []string
		code int
		leak string
	}{
		{name: "unknown-flag-password", args: []string{"--password=synthetic-cli-password"}, code: exitcode.Usage, leak: "synthetic-cli-password"},
		{name: "unknown-flag-json", args: []string{"--json", "--password=synthetic-cli-password"}, code: exitcode.Usage, leak: "synthetic-cli-password"},
		{name: "unknown-command-url", args: []string{"https://demo-user:synthetic-password@internal-host/socket"}, code: exitcode.Usage, leak: "synthetic-password"},
		{name: "unexpected-token-arg", args: []string{"inspect", "synthetic-cli-password"}, code: exitcode.Usage, leak: "synthetic-cli-password"},
	}
	for _, tc := range cases {
		var out, errb bytes.Buffer
		code := Run(tc.args, &out, &errb, nil)
		if code != tc.code {
			t.Fatalf("%s code=%d err=%s", tc.name, code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("%s stdout not empty: %s", tc.name, out.String())
		}
		if strings.Contains(out.String()+errb.String(), tc.leak) {
			t.Fatalf("%s leaked %s in %s", tc.name, tc.leak, errb.String())
		}
	}

	dir := t.TempDir()
	secretFile := filepath.Join(dir, "synthetic-cli-password.env")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--env-file", secretFile})
	if code != exitcode.Input {
		t.Fatalf("missing env-file code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout not empty: %s", out.String())
	}
	if strings.Contains(out.String()+errb.String(), "synthetic-cli-password") {
		t.Fatalf("env-file path leaked: %s", errb.String())
	}
	if !strings.Contains(errb.String(), "<redacted>") && !strings.Contains(errb.String(), "env-file") {
		t.Fatalf("safe diagnostic missing: %s", errb.String())
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"inspect", "--file", filepath.Join(dir, "synthetic-cli-password.yaml")})
	if code != exitcode.Input {
		t.Fatalf("missing file code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 || strings.Contains(out.String()+errb.String(), "synthetic-cli-password") {
		t.Fatalf("file path leaked: out=%s err=%s", out.String(), errb.String())
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"inspect", "--json", "--env-file", secretFile})
	if code != exitcode.Input {
		t.Fatalf("json missing env-file code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 || strings.Contains(out.String()+errb.String(), "synthetic-cli-password") {
		t.Fatalf("json env-file path leaked: out=%s err=%s", out.String(), errb.String())
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"inspect", "--file", filepath.Join(dir, "missing.yaml")})
	if code != exitcode.Input {
		t.Fatalf("safe missing file code=%d", code)
	}
	if !strings.Contains(errb.String(), "missing.yaml") {
		t.Fatalf("safe path should remain visible: %s", errb.String())
	}
}

func TestGoldenInspectShape(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "golden")
	raw, err := os.ReadFile(filepath.Join(root, "inspect-schema.keys.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := strings.Split(strings.TrimSpace(string(raw)), "\n")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Environ: nil, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json"}); code != 0 {
		t.Fatal(errb.String())
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	for _, k := range want {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing key %s", k)
		}
	}
}

func TestInspectNormalizationCanonicalPorts(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "normalize", "ports", "short")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"normalizationDisclaimer"`) || !strings.Contains(out.String(), `published=8000 target=8000 protocol=tcp mode=ingress`) {
		t.Fatalf("inspect normalization %s", out.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.View != "source-level" || len(rep.Normalization) == 0 {
		t.Fatalf("%+v", rep.Normalization)
	}
}

func TestInspectNormalizationSecretProbe(t *testing.T) {
	token := "ghp_ComposeLensNormProbe99xxxxxxxx"
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    labels:\n      API_TOKEN: " + token + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if strings.Contains(out.String(), token) || strings.Contains(errb.String(), token) {
		t.Fatal("raw secret leaked through inspect normalization")
	}
	if !strings.Contains(out.String(), `"redacted": true`) {
		t.Fatalf("expected redacted label %s", out.String())
	}
}

func TestInspectInterpolationGrammarAndPrecedence(t *testing.T) {
	dir := t.TempDir()
	compose := "" +
		"services:\n" +
		"  web:\n" +
		"    image: ${IMAGE}\n" +
		"    hostname: $HOST\n" +
		"    working_dir: ${WORKDIR:-/app}\n" +
		"    user: ${USER-nobody}\n" +
		"    command:\n" +
		"      - ${ENTRY:+start}\n" +
		"      - ${FLAG+on}\n" +
		"      - $$\n" +
		"    environment:\n" +
		"      COLOR: ${COLOR}\n" +
		"      REQUIRED: ${MUST:?must be set}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("COLOR=from-dotenv\nWORKDIR=\nUSER=appuser\nMUST=ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("COLOR=from-envfile\nFLAG=\nUSER=appuser\nMUST=ok\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rt := Runtime{
		Stdout:  &bytes.Buffer{},
		Stderr:  &bytes.Buffer{},
		Cwd:     dir,
		Environ: []string{"IMAGE=nginx:lab", "HOST=web.local", "COLOR=from-shell", "ENTRY=1"},
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	out := rt.Stdout.(*bytes.Buffer)
	errb := rt.Stderr.(*bytes.Buffer)
	if code := rt.Run([]string{"inspect", "--json", "--env-file", extra, "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.View != "source-level" {
		t.Fatalf("view %s", rep.View)
	}
	if !strings.Contains(rep.InterpolationDisclaimer, "interpolation stage only") {
		t.Fatalf("disclaimer %s", rep.InterpolationDisclaimer)
	}
	byPath := map[string]InterpValueReport{}
	for _, it := range rep.Interpolation {
		byPath[it.Path] = it
	}
	check := func(path, resolved, state string) {
		t.Helper()
		it, ok := byPath[path]
		if !ok {
			t.Fatalf("missing %s", path)
		}
		if it.State != state {
			t.Fatalf("%s state=%s want %s", path, it.State, state)
		}
		if it.Value.Redacted || it.Value.Text == nil || *it.Value.Text != resolved {
			t.Fatalf("%s value=%v", path, it.Value.Text)
		}
	}
	check("services.web.image", "nginx:lab", interpStateResolved)
	check("services.web.hostname", "web.local", interpStateResolved)
	check("services.web.working_dir", "/app", interpStateDefaulted)
	check("services.web.user", "appuser", interpStateResolved)
	check("services.web.command[0]", "start", interpStateResolved)
	check("services.web.command[1]", "on", interpStateResolved)
	check("services.web.command[2]", "$", interpStateEscaped)
	check("services.web.environment.COLOR", "from-shell", interpStateResolved)
	check("services.web.environment.REQUIRED", "ok", interpStateResolved)
	color := byPath["services.web.environment.COLOR"]
	if color.Source == nil || color.Source.Stage != "host-shell" {
		t.Fatalf("color source %+v", color.Source)
	}

	out.Reset()
	errb.Reset()
	rt.Environ = []string{"ENTRY=1"}
	if code := rt.Run([]string{"inspect", "--json", "--env-file", extra, "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	byPath = map[string]InterpValueReport{}
	for _, it := range rep.Interpolation {
		byPath[it.Path] = it
	}
	color = byPath["services.web.environment.COLOR"]
	if color.Value.Text == nil || *color.Value.Text != "from-envfile" || color.Source == nil || color.Source.Stage != "env-file" {
		t.Fatalf("env-file color %+v", color)
	}
}

func TestInspectEnvFileReplacesDotenvOnlyVar(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:${TAG}\n    hostname: ${HOSTV}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TAG=1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("HOSTV=repro-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("no env-file code=%d err=%s", code, errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	byPath := map[string]InterpValueReport{}
	for _, it := range rep.Interpolation {
		byPath[it.Path] = it
	}
	img := byPath["services.web.image"]
	if img.Value.Text == nil || *img.Value.Text != "nginx:1.25" {
		t.Fatalf("no --env-file image %+v", img)
	}

	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"inspect", "--json", "--env-file", extra, "--project-directory", dir}); code != 0 {
		t.Fatalf("with env-file code=%d err=%s", code, errb.String())
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	byPath = map[string]InterpValueReport{}
	for _, it := range rep.Interpolation {
		byPath[it.Path] = it
	}
	img = byPath["services.web.image"]
	if img.Value.Text == nil || *img.Value.Text != "nginx:" {
		t.Fatalf("--env-file must drop .env TAG, image=%+v", img)
	}
	host := byPath["services.web.hostname"]
	if host.Value.Text == nil || *host.Value.Text != "repro-host" {
		t.Fatalf("HOSTV from --env-file %+v", host)
	}
	if len(rep.UnappliedSources) != 1 || rep.UnappliedSources[0].Applied || rep.UnappliedSources[0].Stage != "project-env" {
		t.Fatalf("unapplied project .env %+v", rep.UnappliedSources)
	}
	for _, e := range rep.Environment {
		for _, s := range e.Sources {
			if s.Stage == "project-env" {
				t.Fatalf("unselected .env binding still applied: %+v", e)
			}
		}
	}

	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"inspect", "--json", "--env-file", filepath.Join(dir, ".env"), "--project-directory", dir}); code != 0 {
		t.Fatalf("explicit project .env code=%d err=%s", code, errb.String())
	}
	rep = inspectReport{}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if len(rep.UnappliedSources) != 0 {
		t.Fatalf("explicit project .env must not be unapplied %+v", rep.UnappliedSources)
	}
	byPath = map[string]InterpValueReport{}
	for _, it := range rep.Interpolation {
		byPath[it.Path] = it
	}
	img = byPath["services.web.image"]
	if img.Value.Text == nil || *img.Value.Text != "nginx:1.25" {
		t.Fatalf("explicit project .env image %+v", img)
	}
	var envFileStage bool
	for _, e := range rep.Environment {
		for _, s := range e.Sources {
			if s.Stage == "env-file" && e.Key == "TAG" {
				envFileStage = true
			}
			if s.Stage == "project-env" {
				t.Fatalf("explicit .env still labeled project-env: %+v", e)
			}
		}
	}
	if !envFileStage {
		t.Fatal("explicit project .env must appear as env-file")
	}
}

const (
	interpStateResolved  = "resolved"
	interpStateDefaulted = "defaulted"
	interpStateEscaped   = "escaped-literal"
)

func TestInspectBenignInterpolationDefaultEmits(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: \"alpine:${CL_PROBE_TAG:-3.21.3}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("benign interpolation code=%d err=%s out=%s", code, errb.String(), out.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var img InterpValueReport
	for _, it := range rep.Interpolation {
		if it.Path == "services.web.image" {
			img = it
		}
	}
	if img.Raw != "alpine:${CL_PROBE_TAG:-3.21.3}" {
		t.Fatalf("raw %+v", img)
	}
	if img.Value.Text == nil || *img.Value.Text != "alpine:3.21.3" {
		t.Fatalf("resolved %+v", img)
	}
	if img.Value.Redacted {
		t.Fatal("benign interpolation redacted")
	}
}

func TestInspectSecretKeyDefaultWithoutVendorPrefix(t *testing.T) {
	dir := t.TempDir()
	marker := "sample-credential-value-7319"
	compose := "services:\n  web:\n    image: \"alpine:${API_TOKEN:-" + marker + "}\"\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "--json", "--project-directory", dir},
		{"inspect", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, marker) {
			t.Fatalf("%v leaked secret default", args)
		}
		if args[1] == "--json" {
			var rep inspectReport
			if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
				t.Fatal(err)
			}
			var img InterpValueReport
			for _, it := range rep.Interpolation {
				if it.Path == "services.web.image" {
					img = it
				}
			}
			if img.Raw != "[redacted]" || !img.Value.Redacted || img.Value.Text != nil {
				t.Fatalf("secret-designated default still visible %+v", img)
			}
		}
	}
}

func TestInspectSecretDefaultedInterpolationRedacted(t *testing.T) {
	dir := t.TempDir()
	secret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	compose := "services:\n  web:\n    image: \"alpine:${UNSET:-" + secret + "}\"\n    environment:\n      TOKEN: " + secret + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("secret-defaulted code=%d err=%s", code, errb.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(blob, secret) {
		t.Fatal("secret-defaulted interpolation leaked")
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var img InterpValueReport
	for _, it := range rep.Interpolation {
		if it.Path == "services.web.image" {
			img = it
		}
	}
	if img.Raw != "[redacted]" {
		t.Fatalf("secret default raw still visible %+v", img)
	}
	if img.Value.Text != nil {
		t.Fatalf("secret default resolved visible %+v", img)
	}
}

func TestInspectInterpolatedSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: ${IMAGE}\n    environment:\n      TOKEN: ${API_TOKEN}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-interp-token-value"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("API_TOKEN="+secret+"\nIMAGE=nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "--project-directory", dir},
		{"inspect", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, secret) {
			t.Fatalf("%v leaked interpolated secret", args)
		}
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var token InterpValueReport
	for _, it := range rep.Interpolation {
		if strings.HasSuffix(it.Path, "TOKEN") || strings.Contains(it.Path, "API_TOKEN") || it.Path == "services.web.environment.TOKEN" {
			token = it
		}
	}
	if token.Path == "" || !token.Value.Redacted || token.Value.Text != nil {
		t.Fatalf("token not redacted: %+v", token)
	}
}

func TestInspectMergeRules(t *testing.T) {
	dir := t.TempDir()
	base := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    hostname: from-base\n" +
		"    environment:\n" +
		"      A: one\n" +
		"      B: two\n" +
		"    ports:\n" +
		"      - \"80:80\"\n" +
		"      - \"443:443\"\n" +
		"  cache:\n" +
		"    image: redis\n" +
		"    environment:\n" +
		"      OLD: drop-me\n"
	over := "" +
		"services:\n" +
		"  web:\n" +
		"    image: alpine\n" +
		"    environment:\n" +
		"      B: two-b\n" +
		"      C: three\n" +
		"    ports:\n" +
		"      - \"8080:80\"\n"
	reset := "services:\n  cache:\n    environment: !reset {}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.yaml"), []byte(over), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "reset.yaml"), []byte(reset), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	args := []string{"inspect", "--json", "-f", "compose.yaml", "-f", "overlay.yaml", "-f", "reset.yaml", "--project-directory", dir}
	if code := rt.Run(args); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.View != "source-level" {
		t.Fatalf("view %s", rep.View)
	}
	if !strings.Contains(rep.MergeDisclaimer, "multi-file merge after interpolation") {
		t.Fatalf("merge disclaimer %s", rep.MergeDisclaimer)
	}
	if len(rep.Interpolation) == 0 && strings.Contains(base, "$") {
		t.Fatal("interpolation view should remain when expressions exist")
	}
	byPath := map[string]MergeFieldReport{}
	for _, f := range rep.Merge {
		byPath[f.Path] = f
	}
	img := byPath["services.web.image"]
	if img.Value.Text == nil || *img.Value.Text != "alpine" || img.Action != "override" || !strings.HasSuffix(img.Winner, "overlay.yaml") {
		t.Fatalf("image %+v", img)
	}
	host := byPath["services.web.hostname"]
	if host.Value.Text == nil || *host.Value.Text != "from-base" || !strings.HasSuffix(host.Winner, "compose.yaml") {
		t.Fatalf("hostname %+v", host)
	}
	a := byPath["services.web.environment.A"]
	if a.Value.Text == nil || *a.Value.Text != "one" {
		t.Fatalf("A %+v", a)
	}
	b := byPath["services.web.environment.B"]
	if b.Value.Text == nil || *b.Value.Text != "two-b" || b.Action != "override" {
		t.Fatalf("B %+v", b)
	}
	c := byPath["services.web.environment.C"]
	if c.Value.Text == nil || *c.Value.Text != "three" || c.Action != "add" {
		t.Fatalf("C %+v", c)
	}
	ports := byPath["services.web.ports"]
	if ports.Value.Text == nil || *ports.Value.Text != "[80:80, 443:443, 8080:80]" || ports.Action != "append" {
		t.Fatalf("ports %+v", ports)
	}
	env := byPath["services.cache.environment"]
	if env.Action != "reset" {
		t.Fatalf("reset %+v", env)
	}
	if _, ok := byPath["services.cache.environment.OLD"]; ok {
		t.Fatal("reset children remain")
	}
}

func TestInspectMergedSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	base := "services:\n  web:\n    environment:\n      API_TOKEN: synthetic-merge-token-value\n      A: keep\n"
	over := "services:\n  web:\n    environment:\n      API_TOKEN: synthetic-merge-token-overlay\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(base), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "overlay.yaml"), []byte(over), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-merge-token-overlay"
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "-f", "compose.yaml", "-f", "overlay.yaml", "--project-directory", dir},
		{"inspect", "--json", "-f", "compose.yaml", "-f", "overlay.yaml", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, secret) || strings.Contains(blob, "synthetic-merge-token-value") {
			t.Fatalf("%v leaked merged secret", args)
		}
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var tok MergeFieldReport
	for _, f := range rep.Merge {
		if f.Path == "services.web.environment.API_TOKEN" {
			tok = f
		}
	}
	if tok.Path == "" || !tok.Value.Redacted || tok.Value.Text != nil {
		t.Fatalf("merged token not redacted: %+v", tok)
	}
	for _, o := range tok.Overridden {
		if !o.Value.Redacted || o.Value.Text != nil {
			t.Fatalf("overridden secret not redacted: %+v", o)
		}
	}
}

func TestInspectProfilesFlagAndEnv(t *testing.T) {
	dir := t.TempDir()
	compose := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    depends_on: [db]\n" +
		"  debug:\n" +
		"    image: alpine\n" +
		"    profiles: [debug]\n" +
		"  worker:\n" +
		"    image: busybox\n" +
		"    profiles: [debug, tools]\n" +
		"  db:\n" +
		"    image: postgres\n" +
		"    profiles: [storage]\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	lookup := func(rep inspectReport) map[string]ProfileServiceReport {
		m := map[string]ProfileServiceReport{}
		for _, s := range rep.ProfileServices {
			m[s.Name] = s
		}
		return m
	}
	runJSON := func(args []string, environ []string) inspectReport {
		t.Helper()
		var out, errb bytes.Buffer
		rt := Runtime{
			Stdout:  &out,
			Stderr:  &errb,
			Cwd:     dir,
			Environ: environ,
			Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
		}
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		var rep inspectReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	none := lookup(runJSON([]string{"inspect", "--json", "--project-directory", dir}, nil))
	if none["web"].State != "enabled" || none["web"].Reason != "no-profiles (always on)" {
		t.Fatalf("web %+v", none["web"])
	}
	if none["debug"].State != "disabled" || none["worker"].State != "disabled" {
		t.Fatalf("profiled default %+v", none)
	}
	if none["db"].State != "disabled" || none["db"].Certainty != "unknown" || none["db"].ImplicitOf == nil || *none["db"].ImplicitOf != "web" {
		t.Fatalf("inactive-profiled depends_on db %+v", none["db"])
	}
	if !strings.Contains(none["db"].Reason, "required by web via depends_on") {
		t.Fatalf("db reason %s", none["db"].Reason)
	}
	flagged := runJSON([]string{"inspect", "--json", "--profile", "debug", "--project-directory", dir}, nil)
	if len(flagged.ActiveProfiles) != 1 || flagged.ActiveProfiles[0].Name != "debug" || flagged.ActiveProfiles[0].Source != "flag" {
		t.Fatalf("active %+v", flagged.ActiveProfiles)
	}
	fm := lookup(flagged)
	if fm["debug"].State != "enabled" || fm["debug"].Matched == nil || *fm["debug"].Matched != "debug" {
		t.Fatalf("flag debug %+v", fm["debug"])
	}
	if fm["worker"].State != "enabled" {
		t.Fatalf("flag worker %+v", fm["worker"])
	}
	envd := runJSON([]string{"inspect", "--json", "--project-directory", dir}, []string{"COMPOSE_PROFILES=debug"})
	if len(envd.ActiveProfiles) != 1 || envd.ActiveProfiles[0].Source != "COMPOSE_PROFILES" {
		t.Fatalf("env active %+v", envd.ActiveProfiles)
	}
	em := lookup(envd)
	if em["debug"].State != "enabled" || em["debug"].MatchedSource == nil || *em["debug"].MatchedSource != "COMPOSE_PROFILES" {
		t.Fatalf("env debug %+v", em["debug"])
	}
	both := runJSON([]string{"inspect", "--json", "--profile", "tools", "--project-directory", dir}, []string{"COMPOSE_PROFILES=debug"})
	bm := lookup(both)
	if bm["worker"].State != "enabled" || bm["debug"].State != "disabled" {
		t.Fatalf("flags should override env %+v", bm)
	}
}

func TestInspectProfiledSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx\n  debug:\n    image: alpine\n    profiles: [debug]\n    environment:\n      API_TOKEN: synthetic-merge-token-overlay\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	secret := "synthetic-merge-token-overlay"
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "--profile", "debug", "--project-directory", dir},
		{"inspect", "--json", "--profile", "debug", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, secret) {
			t.Fatalf("%v leaked profiled secret", args)
		}
	}
}

func TestInspectIncludesShortLongMultiNestedCycleOverride(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("base.yaml", "services:\n  web:\n    image: included\n    hostname: keep\n")
	write("compose.yaml", "include: base.yaml\nservices:\n  web:\n    image: overridden\n")
	write("long.yaml", "include:\n  path: base.yaml\nservices:\n  web:\n    hostname: local\n")
	write("a.yaml", "services:\n  web:\n    image: one\n    hostname: from-a\n")
	write("b.yaml", "services:\n  web:\n    image: two\n")
	write("multi.yaml", "include:\n  - a.yaml\n  - b.yaml\nservices:\n  web:\n    image: three\n")
	write("inner.yaml", "services:\n  inner:\n    image: alpine\n")
	write("mid.yaml", "include: inner.yaml\nservices:\n  mid:\n    image: busybox\n")
	write("nested.yaml", "include: mid.yaml\nservices:\n  web:\n    image: nginx\n")
	write("cycle-a.yaml", "include: cycle-b.yaml\nservices:\n  a:\n    image: a\n")
	write("cycle-b.yaml", "include: cycle-a.yaml\nservices:\n  b:\n    image: b\n")

	runJSON := func(file string) inspectReport {
		t.Helper()
		var out, errb bytes.Buffer
		rt := Runtime{
			Stdout:  &out,
			Stderr:  &errb,
			Cwd:     dir,
			Environ: nil,
			Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
		}
		if code := rt.Run([]string{"inspect", "--json", "-f", file, "--project-directory", dir}); code != 0 {
			t.Fatalf("%s code=%d err=%s", file, code, errb.String())
		}
		var rep inspectReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	byPath := func(rep inspectReport) map[string]MergeFieldReport {
		m := map[string]MergeFieldReport{}
		for _, f := range rep.Merge {
			m[f.Path] = f
		}
		return m
	}

	short := runJSON("compose.yaml")
	if len(short.Includes) != 1 || len(short.Includes[0].Refs) != 1 || short.Includes[0].Refs[0].State != "ok" || short.Includes[0].Refs[0].Form != "short" {
		t.Fatalf("short graph %+v", short.Includes)
	}
	sm := byPath(short)
	if sm["services.web.image"].Value.Text == nil || *sm["services.web.image"].Value.Text != "overridden" {
		t.Fatalf("short image %+v", sm["services.web.image"])
	}
	host := sm["services.web.hostname"]
	if host.Value.Text == nil || *host.Value.Text != "keep" || len(host.IncludeChain) < 2 {
		t.Fatalf("short hostname %+v", host)
	}

	long := runJSON("long.yaml")
	if len(long.Includes) != 1 || long.Includes[0].Refs[0].Form != "long" || long.Includes[0].Refs[0].State != "ok" {
		t.Fatalf("long graph %+v", long.Includes)
	}

	multi := byPath(runJSON("multi.yaml"))
	if multi["services.web.image"].Value.Text == nil || *multi["services.web.image"].Value.Text != "three" {
		t.Fatalf("multi image %+v", multi["services.web.image"])
	}
	if multi["services.web.hostname"].Value.Text == nil || *multi["services.web.hostname"].Value.Text != "from-a" {
		t.Fatalf("multi hostname %+v", multi["services.web.hostname"])
	}

	nested := runJSON("nested.yaml")
	if len(nested.Includes) != 1 || nested.Includes[0].Refs[0].Nested == nil || len(nested.Includes[0].Refs[0].Nested.Refs) != 1 {
		t.Fatalf("nested graph %+v", nested.Includes)
	}
	nm := byPath(nested)
	if nm["services.inner.image"].Value.Text == nil || *nm["services.inner.image"].Value.Text != "alpine" {
		t.Fatalf("nested %+v", nm)
	}

	cycle := runJSON("cycle-a.yaml")
	if len(cycle.Includes) != 1 || !cycle.Includes[0].HasCycle {
		t.Fatalf("cycle graph %+v", cycle.Includes)
	}
	foundCycle := false
	var walk func(IncludeGraphReport)
	walk = func(g IncludeGraphReport) {
		for _, ref := range g.Refs {
			if ref.State == "cycle" {
				foundCycle = true
			}
			if ref.Nested != nil {
				walk(*ref.Nested)
			}
		}
	}
	walk(cycle.Includes[0])
	if !foundCycle {
		t.Fatalf("no cycle ref %+v", cycle.Includes)
	}
}

func TestInspectIncludedSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	secret := "synthetic-merge-token-overlay"
	if err := os.WriteFile(filepath.Join(dir, "base.yaml"), []byte("services:\n  web:\n    environment:\n      API_TOKEN: "+secret+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("include: base.yaml\nservices:\n  web:\n    image: nginx\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "--project-directory", dir},
		{"inspect", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, secret) {
			t.Fatalf("%v leaked included secret", args)
		}
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	var tok MergeFieldReport
	for _, f := range rep.Merge {
		if f.Path == "services.web.environment.API_TOKEN" {
			tok = f
		}
	}
	if tok.Path == "" || !tok.Value.Redacted || tok.Value.Text != nil {
		t.Fatalf("included token not redacted: %+v", tok)
	}
}

func TestInspectExtendsSameFileCrossFileOverrideCycle(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("compose.yaml", ""+
		"services:\n"+
		"  db:\n"+
		"    image: postgres\n"+
		"  common:\n"+
		"    image: busybox\n"+
		"    hostname: from-base\n"+
		"    depends_on: [db]\n"+
		"    environment:\n"+
		"      TZ: utc\n"+
		"      PORT: \"80\"\n"+
		"  cli:\n"+
		"    extends:\n"+
		"      service: common\n"+
		"    environment:\n"+
		"      PORT: \"8080\"\n")
	write("base.yaml", "services:\n  web:\n    image: nginx\n    hostname: from-file\n")
	write("cross.yaml", "services:\n  web:\n    extends:\n      file: base.yaml\n      service: web\n    image: alpine\n")
	write("cycle.yaml", "services:\n  a:\n    extends:\n      service: b\n    image: a\n  b:\n    extends:\n      service: a\n    image: b\n")

	runJSON := func(file string) inspectReport {
		t.Helper()
		var out, errb bytes.Buffer
		rt := Runtime{
			Stdout:  &out,
			Stderr:  &errb,
			Cwd:     dir,
			Environ: nil,
			Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
		}
		if code := rt.Run([]string{"inspect", "--json", "-f", file, "--project-directory", dir}); code != 0 {
			t.Fatalf("%s code=%d err=%s", file, code, errb.String())
		}
		var rep inspectReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		return rep
	}
	byPath := func(rep inspectReport) map[string]MergeFieldReport {
		m := map[string]MergeFieldReport{}
		for _, f := range rep.Merge {
			m[f.Path] = f
		}
		return m
	}

	same := runJSON("compose.yaml")
	sm := byPath(same)
	if sm["services.cli.image"].Value.Text == nil || *sm["services.cli.image"].Value.Text != "busybox" {
		t.Fatalf("inherited image %+v", sm["services.cli.image"])
	}
	if sm["services.cli.environment.PORT"].Value.Text == nil || *sm["services.cli.environment.PORT"].Value.Text != "8080" {
		t.Fatalf("override PORT %+v", sm["services.cli.environment.PORT"])
	}
	if _, ok := sm["services.cli.depends_on"]; ok {
		t.Fatalf("depends_on inherited %+v", sm["services.cli.depends_on"])
	}
	if sm["services.cli.image"].ExtendsOrigin != "inherited" {
		t.Fatalf("origin %+v", sm["services.cli.image"])
	}
	if len(sm["services.cli.image"].ExtendsChain) != 2 || !strings.HasSuffix(sm["services.cli.image"].ExtendsChain[0], "::cli") || !strings.HasSuffix(sm["services.cli.image"].ExtendsChain[1], "::common") {
		t.Fatalf("chain %+v", sm["services.cli.image"].ExtendsChain)
	}

	cross := byPath(runJSON("cross.yaml"))
	if cross["services.web.image"].Value.Text == nil || *cross["services.web.image"].Value.Text != "alpine" {
		t.Fatalf("cross image %+v", cross["services.web.image"])
	}
	if cross["services.web.hostname"].Value.Text == nil || *cross["services.web.hostname"].Value.Text != "from-file" {
		t.Fatalf("cross hostname %+v", cross["services.web.hostname"])
	}

	cycle := runJSON("cycle.yaml")
	if len(cycle.Extends) != 1 || !cycle.Extends[0].HasCycle {
		t.Fatalf("cycle %+v", cycle.Extends)
	}
}

func TestInspectExtendedSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	secret := "synthetic-merge-token-overlay"
	body := "services:\n  common:\n    image: busybox\n    environment:\n      API_TOKEN: " + secret + "\n  cli:\n    extends:\n      service: common\n    hostname: local\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "--project-directory", dir},
		{"inspect", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, secret) {
			t.Fatalf("%v leaked extended secret", args)
		}
	}
}

func TestInspectContainerEnvOverrideOrderPassThrough(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("a.env", "COLOR=from-a\nSHARED=from-a\n")
	write("b.env", "COLOR=from-b\nSHARED=from-b\n")
	write("compose.yaml", ""+
		"services:\n"+
		"  web:\n"+
		"    image: alpine\n"+
		"    hostname: ${HOST_NAME:-webhost}\n"+
		"    env_file:\n"+
		"      - a.env\n"+
		"      - b.env\n"+
		"    environment:\n"+
		"      - COLOR=from-compose\n"+
		"      - DEBUG\n")
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: []string{"DEBUG=from-shell"},
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep inspectReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.InterpolationDisclaimer == "" || rep.ContainerEnvironmentDisclaimer == "" {
		t.Fatal("stages must stay distinct")
	}
	if strings.Contains(rep.ContainerEnvironmentDisclaimer, "interpolation stage") {
		t.Fatal("container-env disclaimer conflated with interpolation")
	}
	foundHost := false
	for _, it := range rep.Interpolation {
		if it.Path == "services.web.hostname" && it.Value.Text != nil && *it.Value.Text == "webhost" {
			foundHost = true
		}
	}
	if !foundHost {
		t.Fatalf("interpolation hostname missing %+v", rep.Interpolation)
	}
	if len(rep.ContainerEnvironment) != 1 {
		t.Fatalf("services %+v", rep.ContainerEnvironment)
	}
	byKey := map[string]ContainerEnvVarReport{}
	for _, v := range rep.ContainerEnvironment[0].Variables {
		byKey[v.Key] = v
	}
	if byKey["COLOR"].Winner.Kind != "environment" || byKey["COLOR"].Value.Text == nil || *byKey["COLOR"].Value.Text != "from-compose" {
		t.Fatalf("COLOR %+v", byKey["COLOR"])
	}
	if len(byKey["COLOR"].Overridden) < 2 {
		t.Fatalf("COLOR losers %+v", byKey["COLOR"].Overridden)
	}
	if byKey["SHARED"].Value.Text == nil || *byKey["SHARED"].Value.Text != "from-b" {
		t.Fatalf("SHARED %+v", byKey["SHARED"])
	}
	if byKey["DEBUG"].Winner.Kind != "host-shell" || byKey["DEBUG"].Value.Text == nil || *byKey["DEBUG"].Value.Text != "from-shell" {
		t.Fatalf("DEBUG %+v", byKey["DEBUG"])
	}
}

func TestInspectContainerEnvSecretRedacted(t *testing.T) {
	dir := t.TempDir()
	secretE := "synthetic-merge-token-overlay"
	secretF := "synthetic-merge-token-value"
	if err := os.WriteFile(filepath.Join(dir, "s.env"), []byte("API_TOKEN="+secretF+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	body := "services:\n  web:\n    image: alpine\n    env_file: s.env\n    environment:\n      API_TOKEN: " + secretE + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: nil,
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	for _, args := range [][]string{
		{"inspect", "--project-directory", dir},
		{"inspect", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, secretE) || strings.Contains(blob, secretF) {
			t.Fatalf("%v leaked container-env secret", args)
		}
	}
}

func TestReproduceJSONAndHuman(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"reproduce", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep reproduceReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if rep.Schema != "composelens.reproduce.v0" {
		t.Fatalf("schema %s", rep.Schema)
	}
	if len(rep.Argv) < 4 || rep.Argv[0] != "docker" || rep.Argv[1] != "compose" || rep.Argv[len(rep.Argv)-1] != "config" {
		t.Fatalf("argv %v", rep.Argv)
	}
	if !strings.Contains(rep.Command, "docker compose") || !strings.Contains(rep.Command, "config") {
		t.Fatalf("command %s", rep.Command)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"reproduce", "--project-directory", dir}); code != 0 {
		t.Fatalf("human code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), "docker compose") || !strings.Contains(out.String(), "config") {
		t.Fatalf("human %s", out.String())
	}
}

func TestReproduceDoesNotInlineSecret(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"reproduce", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), probe) {
		t.Fatal("raw secret in reproduce output")
	}
}

func TestReproduceEmitsCOMPOSEProfilesAndEnvFiles(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    profiles: [debug]\n  core:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("COLOR=blue\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout:  &out,
		Stderr:  &errb,
		Cwd:     dir,
		Environ: []string{"COMPOSE_PROFILES=debug", "COMPOSE_ENV_FILES=" + extra},
		Detect:  func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	if code := rt.Run([]string{"reproduce", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	var rep reproduceReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(rep.Argv, " ")
	if !strings.Contains(joined, "--profile debug") {
		t.Fatalf("expected materialized --profile, argv=%v", rep.Argv)
	}
	if !strings.Contains(joined, "--env-file") || !strings.Contains(joined, extra) {
		t.Fatalf("expected materialized --env-file, argv=%v", rep.Argv)
	}

	other := filepath.Join(dir, "other.env")
	if err := os.WriteFile(other, []byte("COLOR=explicit\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(dir, "missing.env")
	out.Reset()
	errb.Reset()
	rt.Environ = []string{"COMPOSE_ENV_FILES=" + missing}
	if code := rt.Run([]string{"reproduce", "--json", "--env-file", other, "--project-directory", dir}); code != 0 {
		t.Fatalf("explicit reproduce code=%d err=%s", code, errb.String())
	}
	var over reproduceReport
	if err := json.Unmarshal(out.Bytes(), &over); err != nil {
		t.Fatal(err)
	}
	overJoined := strings.Join(over.Argv, " ")
	if strings.Contains(overJoined, "missing.env") {
		t.Fatalf("predefined missing path must not be materialized: argv=%v", over.Argv)
	}
	if !strings.Contains(overJoined, other) {
		t.Fatalf("explicit --env-file must be materialized: argv=%v", over.Argv)
	}
}

func TestReproduceSecretProfileFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"reproduce", "--profile", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "--project-directory", dir})
	if code != 4 {
		t.Fatalf("code=%d want 4 err=%s out=%s", code, errb.String(), out.String())
	}
	if strings.Contains(out.String()+errb.String(), "ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatal("raw secret-shaped profile in output")
	}
}

func TestDoctorListsReproductionImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	has := false
	for _, f := range rep.Features.Implemented {
		if f == "compose-reproduction" {
			has = true
		}
	}
	if !has {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	for _, f := range rep.Features.Deferred {
		if f == "compose-reproduction" {
			t.Fatal("compose-reproduction still deferred")
		}
	}
}

func TestParseArgsCheckPolicy(t *testing.T) {
	opt, err := ParseArgs([]string{"check", "--policy", "p.yaml", "--project-directory", "proj"})
	if err != nil {
		t.Fatal(err)
	}
	if opt.Command != "check" || opt.Policy != "p.yaml" {
		t.Fatalf("%+v", opt)
	}
}

func TestParseArgsEmptyPolicyIsUsage(t *testing.T) {
	cases := [][]string{
		{"check", "--policy"},
		{"check", "--policy="},
		{"check", "--policy", "   "},
		{"check", "--policy", "--json"},
		{"check", "--policy=   "},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			_, err := ParseArgs(args)
			if err == nil || !strings.Contains(err.Error(), "missing value for --policy") {
				t.Fatalf("args=%v err=%v", args, err)
			}
		})
	}
}

func TestCheckEmptyPolicyFailsBeforeAnalysis(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	cases := [][]string{
		{"check", "--json", "--policy=", "--project-directory", dir},
		{"check", "--json", "--policy", "--json", "--project-directory", dir},
		{"check", "--json", "--policy", "--project-directory", dir},
	}
	for _, args := range cases {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			var out, errb bytes.Buffer
			rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
			code := rt.Run(args)
			if code != exitcode.Usage {
				t.Fatalf("code=%d want 2 err=%s out=%s", code, errb.String(), out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("analysis leaked to stdout: %s", out.String())
			}
			if strings.Contains(errb.String(), `"id": "CHK01"`) || strings.Contains(out.String(), "CHK01") {
				t.Fatalf("analysis findings: err=%s out=%s", errb.String(), out.String())
			}
			if !strings.Contains(errb.String(), "missing value for --policy") {
				t.Fatalf("err=%s", errb.String())
			}
		})
	}
}

func TestCheckPolicyDuplicateAndThresholdFailBeforeAnalysis(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	polDir := t.TempDir()
	files := []struct {
		name string
		kind string
	}{
		{"dup-schema.yaml", "duplicate-field"},
		{"dup-schema.json", "duplicate-field"},
		{"dup-rule-key.yaml", "duplicate-field"},
		{"dup-rule-key.json", "duplicate-field"},
		{"dup-enabled.yaml", "duplicate-field"},
		{"dup-enabled.json", "duplicate-field"},
		{"dup-expires.yaml", "duplicate-field"},
		{"dup-expires.json", "duplicate-field"},
		{"threshold.yaml", "unknown-field"},
		{"threshold.json", "unknown-field"},
	}
	srcDir := filepath.Join("..", "..", "internal", "policy", "testdata")
	for _, tc := range files {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(srcDir, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(polDir, tc.name)
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
			code := rt.Run([]string{"check", "--json", "--policy", p, "--project-directory", dir})
			if code != exitcode.Input {
				t.Fatalf("code=%d want 3 err=%s out=%s", code, errb.String(), out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("analysis leaked to stdout: %s", out.String())
			}
			if strings.Contains(errb.String(), `"id": "CHK01"`) || strings.Contains(errb.String(), "secret-inline") {
				t.Fatalf("analysis findings in error: %s", errb.String())
			}
			if !strings.Contains(errb.String(), "policy:") || !strings.Contains(errb.String(), tc.kind) {
				t.Fatalf("missing typed policy diagnostic: %s", errb.String())
			}
		})
	}
}

func TestCheckMalformedPolicyFailsBeforeAnalysis(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	polDir := t.TempDir()
	files := []struct {
		name string
		kind string
	}{
		{"alpha-omega.yaml", "unknown-field"},
		{"multi-doc.yaml", "multiple-documents"},
		{"alias.yaml", "unsupported-construct"},
		{"merge.yaml", "unsupported-construct"},
		{"cycle.yaml", "unsupported-construct"},
		{"multi-rule.yaml", "unknown-rule"},
		{"multi-exception.yaml", "unknown-field"},
		{"trailing.yaml", "trailing-content"},
		{"trailing.json", "trailing-content"},
	}
	srcDir := filepath.Join("..", "..", "internal", "policy", "testdata")
	for _, tc := range files {
		t.Run(tc.name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(srcDir, tc.name))
			if err != nil {
				t.Fatal(err)
			}
			p := filepath.Join(polDir, tc.name)
			if err := os.WriteFile(p, raw, 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
			code := rt.Run([]string{"check", "--json", "--policy", p, "--project-directory", dir})
			if code != exitcode.Input {
				t.Fatalf("code=%d want 3 err=%s out=%s", code, errb.String(), out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("analysis leaked to stdout: %s", out.String())
			}
			if strings.Contains(errb.String(), `"id": "CHK01"`) || strings.Contains(errb.String(), "secret-inline") {
				t.Fatalf("analysis findings in error: %s", errb.String())
			}
			if !strings.Contains(errb.String(), "policy:") || !strings.Contains(errb.String(), tc.kind) {
				t.Fatalf("missing typed policy diagnostic: %s", errb.String())
			}
		})
	}
}

func TestCheckPolicyAlphaOmegaDeterministic(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	src, err := os.ReadFile(filepath.Join("..", "..", "internal", "policy", "testdata", "alpha-omega.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "ao.yaml")
	if err := os.WriteFile(p, src, 0o644); err != nil {
		t.Fatal(err)
	}
	var first string
	for i := 0; i < 100; i++ {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
		code := rt.Run([]string{"check", "--json", "--policy", p, "--project-directory", dir})
		if code != exitcode.Input || out.Len() != 0 {
			t.Fatalf("i=%d code=%d out=%s err=%s", i, code, out.String(), errb.String())
		}
		msg := errb.String()
		if !strings.Contains(msg, "alpha") || strings.Contains(msg, "omega") {
			t.Fatalf("i=%d diagnostic %s", i, msg)
		}
		if i == 0 {
			first = msg
		} else if msg != first {
			t.Fatalf("stderr drifted\n%s\n%s", first, msg)
		}
	}
}

func TestCheckPolicySecretDuplicateNotEchoed(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	p := filepath.Join(t.TempDir(), "dup.json")
	if err := os.WriteFile(p, []byte(`{"schema":"`+probe+`","schema":"composelens.policy.v0"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--policy", p, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d want 3 err=%s", code, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), probe) {
		t.Fatal("raw secret echoed")
	}
}

func TestPolicyOnlyValidWithCheck(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "p.yaml"), []byte("schema: composelens.policy.v0\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"inspect", "--policy", "p.yaml", "--project-directory", dir})
	if code != exitcode.Usage {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(errb.String(), "--policy is only valid with check") {
		t.Fatalf("err=%s", errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("stdout %s", out.String())
	}
}

func TestCheckPolicyValidApplies(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "env-shadowing")
	polDir := t.TempDir()
	pol := filepath.Join(polDir, "policy.yaml")
	if err := os.WriteFile(pol, []byte("schema: composelens.policy.v0\nrules:\n  - id: CHK05\n    enabled: false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"check", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"id": "CHK05"`) {
		t.Fatalf("baseline %s", out.String())
	}
	if strings.Contains(out.String(), `"policy":`) {
		t.Fatalf("without --policy must omit policy key: %s", out.String())
	}
	if !strings.Contains(out.String(), `"ruleset": "fixed-v0"`) {
		t.Fatalf("without --policy ruleset %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"check", "--json", "--policy", pol, "--project-directory", dir}); code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if strings.Contains(out.String(), `"id": "CHK05"`) {
		t.Fatalf("CHK05 still present: %s", out.String())
	}
	if !strings.Contains(out.String(), `"policy": "composelens.policy.v0"`) || !strings.Contains(out.String(), `"ruleset": "policy-v0"`) {
		t.Fatalf("policy metadata %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"check", "--sarif", "--policy", pol, "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if err := check.ValidateSARIF(out.Bytes()); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"check", "--policy", pol, "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), "policy-v0") {
		t.Fatalf("human %s", out.String())
	}
}

func TestCheckPolicyInvalidFailsBeforeAnalysis(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	polDir := t.TempDir()
	cases := []struct {
		name string
		body string
		kind string
	}{
		{"missing-schema", "rules: []\n", "missing-schema"},
		{"unknown-schema", "schema: composelens.policy.v1\n", "unknown-schema"},
		{"unknown-rule", "schema: composelens.policy.v0\nrules:\n  - id: CHK99\n", "unknown-rule"},
		{"unknown-field", "schema: composelens.policy.v0\nfoo: 1\n", "unknown-field"},
		{"malformed", "{not json", "malformed"},
		{"exception-past", "schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n    expires: \"2020-01-01\"\n", "exception-date"},
		{"exception-missing", "schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n", "exception-date"},
		{"exception-invalid", "schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n    expires: nope\n", "exception-date"},
		{"threshold", "schema: composelens.policy.v0\nrules:\n  - id: CHK01\n    threshold: 1\n", "unknown-field"},
		{"unknown-gate", "schema: composelens.policy.v0\ngate: fatal\n", "invalid-rule"},
		{"dup-schema", "schema: composelens.policy.bad\nschema: composelens.policy.v0\n", "duplicate-field"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := filepath.Join(polDir, tc.name+".yaml")
			if err := os.WriteFile(p, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			var out, errb bytes.Buffer
			rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
			code := rt.Run([]string{"check", "--json", "--policy", p, "--project-directory", dir})
			if code != exitcode.Input {
				t.Fatalf("code=%d want 3 err=%s out=%s", code, errb.String(), out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("analysis leaked to stdout: %s", out.String())
			}
			if strings.Contains(errb.String(), `"id": "CHK01"`) || strings.Contains(errb.String(), "secret-inline") {
				t.Fatalf("analysis findings in error: %s", errb.String())
			}
			if !strings.Contains(errb.String(), "policy:") || !strings.Contains(errb.String(), tc.kind) {
				t.Fatalf("missing typed policy diagnostic: %s", errb.String())
			}
		})
	}
}

func TestCheckPolicySecretNotEchoed(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	p := filepath.Join(t.TempDir(), "bad.yaml")
	if err := os.WriteFile(p, []byte("schema: composelens.policy.v0\n"+probe+": true\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--policy", p, "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d want 3 err=%s", code, errb.String())
	}
	if strings.Contains(out.String()+errb.String(), probe) {
		t.Fatal("raw secret echoed")
	}
}

func TestDoctorListsPolicyLoadingImplemented(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"doctor", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	var rep doctorReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	has := false
	for _, f := range rep.Features.Implemented {
		if f == "compose-policy-loading" {
			has = true
		}
	}
	if !has {
		t.Fatalf("implemented %v", rep.Features.Implemented)
	}
	still := false
	for _, f := range rep.Features.Deferred {
		if f == "policy-engine" {
			still = true
		}
		if f == "compose-policy-loading" {
			t.Fatal("compose-policy-loading still deferred")
		}
	}
	if !still {
		t.Fatal("policy-engine should remain deferred")
	}
}

func TestFlagContractNamedReproductions(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "secret-inline")
	detectCalls := 0
	rt := func() Runtime {
		return Runtime{
			Cwd: dir,
			Detect: func() engine.Info {
				detectCalls++
				t.Fatal("engine detect must not run on usage failures")
				return engine.Info{}
			},
		}
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"version-inapplicable-env-file", []string{"version", "--json", "--env-file", "definitely-missing.env"}, "--env-file is not valid with version"},
		{"inspect-diff-only-flag", []string{"inspect", "--left-profile", "should-be-rejected", "--project-directory", dir}, "--left-profile is not valid with inspect"},
		{"doctor-empty-project-directory", []string{"doctor", "--project-directory="}, "missing value for --project-directory"},
		{"inspect-env-file-swallows-flag", []string{"inspect", "--env-file", "--json", "--project-directory", dir}, "missing value for --env-file"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			detectCalls = 0
			var out, errb bytes.Buffer
			r := rt()
			r.Stdout, r.Stderr = &out, &errb
			code := r.Run(tc.args)
			if code != exitcode.Usage {
				t.Fatalf("code=%d want 2 err=%s out=%s", code, errb.String(), out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("stdout=%s", out.String())
			}
			if !strings.Contains(errb.String(), tc.want) {
				t.Fatalf("err=%s want %s", errb.String(), tc.want)
			}
			if strings.Contains(errb.String(), `"id": "CHK01"`) || strings.Contains(errb.String(), "secret-inline") {
				t.Fatalf("analysis leaked: %s", errb.String())
			}
			if detectCalls != 0 {
				t.Fatal("engine called")
			}
		})
	}
	t.Run("double-dash-version", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := Run([]string{"--", "version", "--json"}, &out, &errb, nil)
		if code != exitcode.Usage {
			t.Fatalf("operands after -- must not be flags: code=%d err=%s", code, errb.String())
		}
		if out.Len() != 0 {
			t.Fatalf("stdout=%s", out.String())
		}
		if !strings.Contains(errb.String(), "unexpected argument") {
			t.Fatalf("err=%s", errb.String())
		}
		out.Reset()
		errb.Reset()
		code = Run([]string{"--", "version"}, &out, &errb, nil)
		if code != 0 {
			t.Fatalf("-- version: code=%d err=%s", code, errb.String())
		}
		if !strings.Contains(out.String(), "composelens") {
			t.Fatalf("out=%s", out.String())
		}
		out.Reset()
		errb.Reset()
		code = Run([]string{"--json", "--", "version"}, &out, &errb, nil)
		if code != 0 {
			t.Fatalf("--json -- version: code=%d err=%s", code, errb.String())
		}
		if !strings.Contains(out.String(), `"schema": "composelens.version.v0"`) {
			t.Fatalf("out=%s", out.String())
		}
	})
}

func TestFlagContractNegativeMatrix(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	type row struct {
		args []string
		msg  string
	}
	rows := []row{
		{[]string{"version", "--project-directory", dir}, "--project-directory is not valid with version"},
		{[]string{"version", "-f", "compose.yaml"}, "--file is not valid with version"},
		{[]string{"version", "--profile", "debug"}, "--profile is not valid with version"},
		{[]string{"version", "--sarif"}, "--sarif is only valid with check"},
		{[]string{"version", "--github"}, "--github is only valid with check"},
		{[]string{"version", "--bundle", "b.json"}, "--bundle is only valid with doctor"},
		{[]string{"version", "--policy", "p.yaml"}, "--policy is only valid with check"},
		{[]string{"version", "--redact", "r.yaml"}, "--redact is not valid with version"},
		{[]string{"version", "--all"}, "--all is only valid with explain"},
		{[]string{"doctor", "--left-profile", "a"}, "--left-profile is not valid with doctor"},
		{[]string{"doctor", "--right-profile", "a"}, "--right-profile is not valid with doctor"},
		{[]string{"doctor", "--left-env-file", "e.env"}, "--left-env-file is not valid with doctor"},
		{[]string{"doctor", "--right-env-file", "e.env"}, "--right-env-file is not valid with doctor"},
		{[]string{"doctor", "--sarif"}, "--sarif is only valid with check"},
		{[]string{"doctor", "--github"}, "--github is only valid with check"},
		{[]string{"inspect", "--bundle", "b.json", "--project-directory", dir}, "--bundle is only valid with doctor"},
		{[]string{"doctor", "--bundle"}, "missing value for --bundle"},
		{[]string{"doctor", "--bundle="}, "missing value for --bundle"},
		{[]string{"doctor", "--bundle", "--json"}, "missing value for --bundle"},
		{[]string{"doctor", "--json", "--bundle", "b.json"}, "--json and --bundle are mutually exclusive"},
		{[]string{"inspect", "--right-profile", "a", "--project-directory", dir}, "--right-profile is not valid with inspect"},
		{[]string{"explain", "--left-profile", "a", "web"}, "--left-profile is not valid with explain"},
		{[]string{"check", "--all", "--project-directory", dir}, "--all is only valid with explain"},
		{[]string{"diff", "--sarif", "--project-directory", dir}, "--sarif is only valid with check"},
		{[]string{"inspect", "--github", "--project-directory", dir}, "--github is only valid with check"},
		{[]string{"check", "--sarif", "--github", "--project-directory", dir}, "--sarif and --github are mutually exclusive"},
		{[]string{"report", "--github"}, "--github is only valid with check"},
		{[]string{"differential", "--policy", "p.yaml", "--project-directory", dir}, "--policy is only valid with check"},
		{[]string{"reproduce", "--all", "--project-directory", dir}, "--all is only valid with explain"},
		{[]string{"report", "--left-profile", "a"}, "--left-profile is not valid with report"},
		{[]string{"inspect", "--html"}, "--html is only valid with report"},
		{[]string{"report", "--json", "--html"}, "--json and --html are mutually exclusive"},
		{[]string{"inspect", "--project-directory="}, "missing value for --project-directory"},
		{[]string{"inspect", "--project-directory", "--json"}, "missing value for --project-directory"},
		{[]string{"inspect", "--file="}, "missing value for --file"},
		{[]string{"inspect", "-f", "--json"}, "missing value for -f"},
		{[]string{"inspect", "--env-file="}, "missing value for --env-file"},
		{[]string{"inspect", "--profile="}, "missing value for --profile"},
		{[]string{"inspect", "--profile", "--json"}, "missing value for --profile"},
		{[]string{"diff", "--left-profile="}, "missing value for --left-profile"},
		{[]string{"diff", "--left-profile", "--json"}, "missing value for --left-profile"},
		{[]string{"diff", "--right-profile="}, "missing value for --right-profile"},
		{[]string{"diff", "--right-profile", "--json"}, "missing value for --right-profile"},
		{[]string{"diff", "--left-env-file="}, "missing value for --left-env-file"},
		{[]string{"diff", "--left-env-file", "--json"}, "missing value for --left-env-file"},
		{[]string{"diff", "--right-env-file="}, "missing value for --right-env-file"},
		{[]string{"diff", "--right-env-file", "--json"}, "missing value for --right-env-file"},
		{[]string{"check", "--policy"}, "missing value for --policy"},
		{[]string{"check", "--policy="}, "missing value for --policy"},
		{[]string{"check", "--policy", "--json"}, "missing value for --policy"},
		{[]string{"inspect", "--redact="}, "missing value for --redact"},
		{[]string{"inspect", "--redact", "--json"}, "missing value for --redact"},
		{[]string{"inspect", "--file"}, "missing value for --file"},
		{[]string{"version", "extra"}, "unexpected argument"},
	}
	for _, tc := range rows {
		t.Run(strings.Join(tc.args, " "), func(t *testing.T) {
			var out, errb bytes.Buffer
			rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info {
				t.Fatal("engine detect on usage")
				return engine.Info{}
			}}
			code := rt.Run(tc.args)
			if code != exitcode.Usage {
				t.Fatalf("code=%d err=%s out=%s", code, errb.String(), out.String())
			}
			if out.Len() != 0 {
				t.Fatalf("stdout=%s", out.String())
			}
			if !strings.Contains(errb.String(), tc.msg) {
				t.Fatalf("err=%s want %s", errb.String(), tc.msg)
			}
		})
	}
}

func TestFlagContractPositiveStillWorks(t *testing.T) {
	dir := filepath.Join("..", "..", "fixtures", "check", "clean")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	if code := rt.Run([]string{"version", "--json"}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.version.v0"`) {
		t.Fatalf("version %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.inspect.v0"`) {
		t.Fatalf("inspect %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.graph.v0"`) {
		t.Fatalf("explain %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"diff", "--json", "--left-profile", "a", "--right-profile", "b", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.diff.v0"`) {
		t.Fatalf("diff %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"check", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.check.v0"`) {
		t.Fatalf("check %s", out.String())
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"--github", "--", "check"}); code != 0 {
		t.Fatal(errb.String())
	}
	out.Reset()
	errb.Reset()
	bundle := filepath.Join(t.TempDir(), "composelens-support.json")
	if code := rt.Run([]string{"doctor", "--bundle", bundle, "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if _, err := os.Stat(bundle); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"reproduce", "--json", "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.reproduce.v0"`) {
		t.Fatalf("reproduce %s", out.String())
	}
	out.Reset()
	errb.Reset()
	pol, err := filepath.Abs(filepath.Join("..", "..", "examples", "policy-lab", "valid.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if code := rt.Run([]string{"check", "--json", "--policy", pol, "--project-directory", dir}); code != 0 {
		t.Fatal(errb.String())
	}
	opt, err := ParseArgs([]string{"inspect", "--env-file", "real.env", "--project-directory", dir})
	if err != nil {
		t.Fatal(err)
	}
	if len(opt.EnvFiles) != 1 || opt.EnvFiles[0] != "real.env" {
		t.Fatalf("%+v", opt)
	}
}

func TestDottedServiceIdentitySurfaces(t *testing.T) {
	dotted := filepath.Join("..", "..", "fixtures", "identity", "dotted")
	coll := filepath.Join("..", "..", "fixtures", "identity", "collision")
	rt := func(dir string) Runtime {
		return Runtime{Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }, Cwd: dir}
	}
	var out, errb bytes.Buffer
	run := func(dir string, args []string) string {
		out.Reset()
		errb.Reset()
		r := rt(dir)
		r.Stdout, r.Stderr = &out, &errb
		if code := r.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		return out.String()
	}
	ins := run(dotted, []string{"inspect", "--json", "--project-directory", dotted})
	var irep inspectReport
	if err := json.Unmarshal([]byte(ins), &irep); err != nil {
		t.Fatal(err)
	}
	if len(irep.Services) != 1 || irep.Services[0].Name != "web.api" {
		t.Fatalf("inspect services %+v", irep.Services)
	}
	for _, s := range irep.ProfileServices {
		if s.Name != "web.api" {
			t.Fatalf("profile %q", s.Name)
		}
	}
	for _, s := range irep.Normalization {
		if s.Service != "web.api" {
			t.Fatalf("norm %q", s.Service)
		}
	}
	for _, s := range irep.ContainerEnvironment {
		if s.Service != "web.api" {
			t.Fatalf("cenv %q", s.Service)
		}
	}
	ex := run(dotted, []string{"explain", "--json", "web.api", "--project-directory", dotted})
	if !strings.Contains(ex, `"effective":`) || strings.Contains(ex, `"stages": []`) {
		t.Fatalf("explain empty %s", ex)
	}
	if !strings.Contains(ex, `"service": "web.api"`) {
		t.Fatalf("explain target %s", ex)
	}
	g := run(dotted, []string{"explain", "--all", "--json", "--project-directory", dotted})
	if !strings.Contains(g, `"target": "web.api"`) || strings.Contains(g, `"target": "web"`) {
		t.Fatalf("graph %s", g)
	}
	d := run(dotted, []string{"diff", "--json", "--project-directory", dotted})
	if strings.Contains(d, `"target": "web"`) && !strings.Contains(d, "web.api") {
		t.Fatalf("diff %s", d)
	}
	ck := run(dotted, []string{"check", "--json", "--project-directory", dotted})
	if strings.Contains(ck, `"target": "web"`) && !strings.Contains(ck, "web.api") {
		t.Fatalf("check %s", ck)
	}
	cins := run(coll, []string{"inspect", "--json", "--project-directory", coll})
	if !strings.Contains(cins, `"name": "web"`) || !strings.Contains(cins, `"name": "web.api"`) {
		t.Fatalf("collision inspect %s", cins)
	}
	cg := run(coll, []string{"explain", "--all", "--json", "--project-directory", coll})
	if !strings.Contains(cg, `"target": "web"`) || !strings.Contains(cg, `"target": "web.api"`) {
		t.Fatalf("collision graph %s", cg)
	}
}
