// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/check"
	"composelens/internal/evidence"
)

func TestHTMLZeroRemoteRefs(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if refs := RemoteRefs(page); len(refs) > 0 {
		t.Fatalf("remote refs: %v", refs)
	}
	if !bytes.HasPrefix(page, []byte(htmlDoctype)) {
		t.Fatal("missing doctype")
	}
	if bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
		t.Fatal("renderer must not use innerHTML")
	}
}

func TestHTMLInertEmbedding(t *testing.T) {
	pkg := samplePackage()
	pkg.Source.Services[0].Name = `<script>alert(1)</script>`
	pkg.Source.Services[0].Identity = `services.</script>`
	pkg.Check.Findings = []check.FindingReport{{
		ID:       "CHK01",
		Severity: "warning",
		Target:   `"><img onerror=alert(1)>`,
		Message:  `</script><script>alert(1)</script>`,
		Evidence: evidence.Known,
	}}
	raw, err := Encode(pkg)
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("<script>alert")) {
		t.Fatal("raw script tag escaped into executable HTML")
	}
	if bytes.Contains(page, []byte("<img")) {
		t.Fatal("img onerror payload escaped into markup")
	}
	if bytes.Contains(page, []byte("</script><script>")) {
		t.Fatal("script breakout in HTML")
	}
	island, err := DataIslandJSON(page)
	if err != nil {
		t.Fatal(err)
	}
	var round Package
	if err := json.Unmarshal(island, &round); err != nil {
		t.Fatal(err)
	}
	if round.Source.Services[0].Name != `<script>alert(1)</script>` {
		t.Fatalf("name round-trip %q", round.Source.Services[0].Name)
	}
	if round.Check.Findings[0].Target != `"><img onerror=alert(1)>` {
		t.Fatalf("target round-trip %q", round.Check.Findings[0].Target)
	}
	if round.Check.Findings[0].Message != `</script><script>alert(1)</script>` {
		t.Fatalf("message round-trip %q", round.Check.Findings[0].Message)
	}
	if !bytes.Contains(page, []byte(".textContent")) {
		t.Fatal("renderer must assign textContent")
	}
}

func TestHTMLDeterministic(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	a, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("HTML not byte-identical")
	}
}

func TestHTMLRejectsInvalidPackage(t *testing.T) {
	_, err := HTML([]byte(`{"schema":"nope"}`))
	if err == nil || !strings.Contains(err.Error(), "report:") {
		t.Fatalf("want validation error, got %v", err)
	}
}

func TestRemoteRefsFailClosed(t *testing.T) {
	hits := RemoteRefs([]byte(`<!DOCTYPE html><html><body><script>fetch("https://example.invalid")</script></body></html>`))
	if len(hits) == 0 {
		t.Fatal("RemoteRefs must detect fetch(")
	}
}

func TestHTMLKeyboardViewsAndJourneys(t *testing.T) {
	raw, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if refs := RemoteRefs(page); len(refs) > 0 {
		t.Fatalf("remote refs: %v", refs)
	}
	lower := bytes.ToLower(page)
	if bytes.Contains(lower, []byte("innerhtml")) {
		t.Fatal("renderer must not use innerHTML")
	}
	if bytes.Contains(lower, []byte("onmouseover")) || bytes.Contains(lower, []byte("onmouseenter")) {
		t.Fatal("mouse-only handlers")
	}
	need := []string{
		`role="tablist"`,
		`data-view="graph"`,
		`data-view="source"`,
		`data-view="diff"`,
		`data-view="diagnostics"`,
		`role="tab"`,
		`role="tabpanel"`,
		`role="listbox"`,
		`setAttribute("role","option")`,
		`addEventListener("keydown"`,
		`addEventListener("click"`,
		"ArrowLeft",
		"ArrowRight",
		"ArrowUp",
		"ArrowDown",
		"Escape",
		"Enter",
		`:focus`,
		`outline:3px solid`,
		`id="graph-list"`,
		`id="source-list"`,
		`id="findings-list"`,
		`id="diff-list"`,
		`id="diagnostics-list"`,
		`.textContent`,
		`createElement`,
		`tabindex="0"`,
		`tabindex="-1"`,
	}
	for _, s := range need {
		if !bytes.Contains(page, []byte(s)) {
			t.Fatalf("missing %q", s)
		}
	}
	if !bytes.Contains(page, []byte(`e.key===K.space`)) && !bytes.Contains(page, []byte(`e.key===K.space || e.key==="Spacebar"`)) {
		t.Fatal("Space key not handled")
	}
}

func TestHTMLInteractivePackageRoundTrip(t *testing.T) {
	raw, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	island, err := DataIslandJSON(page)
	if err != nil {
		t.Fatal(err)
	}
	var round Package
	if err := json.Unmarshal(island, &round); err != nil {
		t.Fatal(err)
	}
	if len(round.Graph.Nodes) == 0 || len(round.Graph.Nodes[0].ShadowChain) < 2 {
		t.Fatalf("graph round-trip nodes=%d", len(round.Graph.Nodes))
	}
	if round.Graph.Nodes[0].ShadowChain[0].Role != "winner" {
		t.Fatalf("winner role=%q", round.Graph.Nodes[0].ShadowChain[0].Role)
	}
	if len(round.Check.Findings) == 0 || round.Check.Findings[0].Target != "services.web" {
		t.Fatalf("findings=%+v", round.Check.Findings)
	}
	if round.Diagnostics[0].Doc != "docs/check.md" {
		t.Fatalf("doc=%q", round.Diagnostics[0].Doc)
	}
}

func TestHTMLAccessibleNamesLandmarksAndLive(t *testing.T) {
	raw, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	need := []string{
		`lang="en"`,
		`<title>ComposeLens report</title>`,
		`id="skip-to-content"`,
		`href="#main"`,
		`Skip to report views`,
		`<main id="main"`,
		`<h1>ComposeLens report</h1>`,
		`id="heading-graph"`,
		`id="heading-source"`,
		`id="heading-diff"`,
		`id="heading-diagnostics"`,
		`aria-label="Report views"`,
		`aria-label="Graph, provenance and shadow-chains"`,
		`aria-label="Source, source chain"`,
		`aria-label="Diff, differential"`,
		`aria-label="Diagnostics"`,
		`aria-label="Diagnostic entries"`,
		`aria-label="Graph nodes"`,
		`aria-label="Services"`,
		`aria-label="Check findings"`,
		`aria-label="Graph targets"`,
		`aria-label="Differential rows"`,
		`aria-label="Expanded shadow-chain"`,
		`aria-label="Selected source chain"`,
		`aria-label="Selected differential row"`,
		`aria-label="Selected diagnostic"`,
		`aria-labelledby="heading-graph`,
		`id="graph-sr"`,
		`id="source-sr"`,
		`id="diff-sr"`,
		`id="diagnostics-sr"`,
		`aria-live="polite"`,
		`id="live"`,
		`prefers-reduced-motion: reduce`,
		`function announce(`,
		`setAttribute("aria-label","Documentation reference")`,
		`Provenance graph: `,
		`Source chain: `,
		`Diff: `,
		`Diagnostics: `,
		`ArrowDown`,
		`Escape`,
	}
	for _, s := range need {
		if !bytes.Contains(page, []byte(s)) {
			t.Fatalf("missing %q", s)
		}
	}
	if bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
		t.Fatal("innerHTML")
	}
	if refs := RemoteRefs(page); len(refs) > 0 {
		t.Fatalf("remote refs: %v", refs)
	}
	skipAt := bytes.Index(page, []byte(`id="skip-to-content"`))
	tabAt := bytes.Index(page, []byte(`id="tab-graph"`))
	if skipAt < 0 || tabAt < 0 || skipAt > tabAt {
		t.Fatalf("skip must precede Graph tab in markup skip=%d tab=%d", skipAt, tabAt)
	}
	if !bytes.Contains(page, []byte(`<main id="main"`)) {
		t.Fatal("main landmark missing")
	}
	if bytes.Contains(page, []byte(`tabindex="1"`)) || bytes.Contains(page, []byte(`tabindex="2"`)) {
		t.Fatal("positive tabindex can create a focus trap")
	}
	if bytes.Contains(page, []byte("Keyboard journeys")) || bytes.Contains(page, []byte("Keyboard: Left/Right")) {
		t.Fatal("visible keyboard tutorial chrome")
	}
}

func TestHTMLFindNodeUsesExactIdentities(t *testing.T) {
	raw, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(page, []byte("nt.indexOf(t)===0 || t.indexOf(nt)===0")) {
		t.Fatal("prefix fallback still present")
	}
	if !bytes.Contains(page, []byte("function mapServiceIdentity(")) {
		t.Fatal("missing service-identity mapper")
	}
	if !bytes.Contains(page, []byte(`showSourceFor(svc.name||mapServiceIdentity(svc.identity||"")||svc.identity||"", "service")`)) {
		t.Fatal("source rows must map service identities explicitly")
	}
	if !bytes.Contains(page, []byte("showSourceFor(node.target||\"\", node.kind||\"\")")) {
		t.Fatal("graph target rows must pass kind with target")
	}
}

func TestHTMLContrastPaletteShipped(t *testing.T) {
	raw, err := Encode(samplePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []string{ColorText, ColorBg, ColorCard, ColorNote, ColorTabBg, ColorBrand, ColorFocus, ColorUIBorder, ColorError, ColorWarn, ColorOkFg, ColorOkBg, ColorAmberBg, ColorErrBg, ColorChipBg} {
		if !bytes.Contains(page, []byte(c)) {
			t.Fatalf("shipped HTML missing palette color %s", c)
		}
	}
}
