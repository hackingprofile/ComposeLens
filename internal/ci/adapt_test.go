// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/check"
	"composelens/internal/exitcode"
)

func secretInlineResult() check.Result {
	return check.Result{Findings: []check.Finding{{
		ID:       check.CHK01,
		Severity: check.SevWarning,
		Target:   "web:API_TOKEN",
		Kind:     "environment",
		Message:  "secret-keyed or secret-looking value is defined inline in the Compose model; use an external secret source instead",
		Secret:   true,
		File:     "compose.yaml",
		Line:     5,
		Column:   7,
	}}}
}

func TestAnnotationsMatchSARIFPhysicalLocation(t *testing.T) {
	clearGitHubEnv(t)
	r := secretInlineResult()
	raw, err := check.SARIF(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := check.ValidateSARIF(raw); err != nil {
		t.Fatal(err)
	}
	uri := check.PhysicalURI(r, r.Findings[0])
	if uri != "compose.yaml" {
		t.Fatalf("PhysicalURI=%q", uri)
	}
	var log struct {
		Runs []struct {
			Results []struct {
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct {
							URI string `json:"uri"`
						} `json:"artifactLocation"`
						Region *struct {
							StartLine   int `json:"startLine"`
							StartColumn int `json:"startColumn"`
						} `json:"region"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(raw, &log); err != nil {
		t.Fatal(err)
	}
	pl := log.Runs[0].Results[0].Locations[0].PhysicalLocation
	if pl.ArtifactLocation.URI != "compose.yaml" {
		t.Fatalf("sarif uri=%q", pl.ArtifactLocation.URI)
	}
	if pl.Region == nil || pl.Region.StartLine != 5 {
		t.Fatalf("sarif region=%+v", pl.Region)
	}
	bundle, err := FromResult(r, ArtifactLinks{JSON: "composelens-check.json", SARIF: "composelens-check.sarif", Summary: "composelens-check.md"})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Annotations) != 1 {
		t.Fatalf("anns=%d", len(bundle.Annotations))
	}
	a := bundle.Annotations[0]
	if a.Level != "warning" || a.File != pl.ArtifactLocation.URI || a.Line != pl.Region.StartLine {
		t.Fatalf("annotation %+v vs sarif uri=%s line=%d", a, pl.ArtifactLocation.URI, pl.Region.StartLine)
	}
	line := FormatAnnotation(a)
	if line != "::warning file=compose.yaml,line=5,col=7::CHK01 web:API_TOKEN: secret-keyed or secret-looking value is defined inline in the Compose model; use an external secret source instead" {
		t.Fatalf("command=%q", line)
	}
	if strings.Contains(line, `C:`) || strings.Contains(line, `\Users\`) || strings.Contains(string(bundle.Log), `C:\`) {
		t.Fatalf("absolute path in annotations: %s", bundle.Log)
	}
}

func TestAnnotationDoesNotEmitAbsoluteMachinePath(t *testing.T) {
	clearGitHubEnv(t)
	r := secretInlineResult()
	r.Findings[0].File = `C:\Users\x\proj\compose.yaml`
	uri := check.PhysicalURI(r, r.Findings[0])
	if strings.Contains(uri, `\`) || strings.Contains(uri, "Users") || strings.Contains(uri, ":/") {
		t.Fatalf("uri=%q", uri)
	}
	bundle, err := FromResult(r, ArtifactLinks{})
	if err != nil {
		t.Fatal(err)
	}
	log := string(bundle.Log)
	if strings.Contains(log, `C:\`) || strings.Contains(log, `\Users\`) || strings.Contains(log, "/Users/") {
		t.Fatalf("absolute path leaked: %s", log)
	}
	if uri == "compose.yaml" && !strings.Contains(log, "file=compose.yaml,line=5") {
		t.Fatalf("want repo-relative compose.yaml:5, got %s", log)
	}
}

func TestSummaryAndAnnotationsSecretSafeAndArtifactLinks(t *testing.T) {
	clearGitHubEnv(t)
	const secret = "demo-inline"
	r := secretInlineResult()
	bundle, err := FromResult(r, ArtifactLinks{})
	if err != nil {
		t.Fatal(err)
	}
	blob := string(bundle.Log) + bundle.Summary + string(bundle.JSON) + string(bundle.SARIF)
	if strings.Contains(blob, secret) {
		t.Fatal("demo-inline leaked")
	}
	if !strings.Contains(bundle.Summary, "composelens-check.json") || !strings.Contains(bundle.Summary, "composelens-check.sarif") {
		t.Fatalf("missing artifact links:\n%s", bundle.Summary)
	}
	if !strings.Contains(bundle.Summary, "compose.yaml:5") {
		t.Fatalf("summary missing location:\n%s", bundle.Summary)
	}
	if !strings.Contains(bundle.Summary, "CHK01") {
		t.Fatal("summary missing finding")
	}
}

func TestWaivedFindingsSkipAnnotations(t *testing.T) {
	r := secretInlineResult()
	r.Findings[0].Waived = true
	bundle, err := FromResult(r, ArtifactLinks{})
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.Annotations) != 0 || strings.Contains(string(bundle.Log), "::warning") {
		t.Fatalf("waived emitted: %s", bundle.Log)
	}
	if !strings.Contains(bundle.Summary, "## Waived") {
		t.Fatalf("summary=%s", bundle.Summary)
	}
}

func TestEscapeWorkflowCommand(t *testing.T) {
	got := FormatAnnotation(Annotation{Level: "error", File: "a,b:c.yaml", Line: 1, Message: "100%\nnext"})
	if !strings.HasPrefix(got, "::error file=a%2Cb%3Ac.yaml,line=1::") {
		t.Fatalf("%q", got)
	}
	if !strings.Contains(got, "100%25%0Anext") {
		t.Fatalf("%q", got)
	}
}

func TestMapActionExit(t *testing.T) {
	warn := secretInlineResult()
	if got := MapActionExit(exitcode.OK, warn, "error"); got != exitcode.OK {
		t.Fatalf("error fail-on warning-only: %d", got)
	}
	if got := MapActionExit(exitcode.OK, warn, "warning"); got != exitcode.Assertion {
		t.Fatalf("warning fail-on: %d", got)
	}
	if got := MapActionExit(exitcode.Assertion, warn, "never"); got != exitcode.OK {
		t.Fatalf("never: %d", got)
	}
	if got := MapActionExit(exitcode.Input, warn, "never"); got != exitcode.Input {
		t.Fatalf("input preserved: %d", got)
	}
}

func TestLinksFromEnvBasename(t *testing.T) {
	t.Setenv(EnvJSONPath, `C:\tmp\out.json`)
	t.Setenv(EnvSARIFPath, "/tmp/out.sarif")
	t.Setenv(EnvSummaryPath, "")
	links := LinksFromEnv()
	if links.JSON != "out.json" || links.SARIF != "out.sarif" || links.Summary != defaultSummaryName {
		t.Fatalf("%+v", links)
	}
}
