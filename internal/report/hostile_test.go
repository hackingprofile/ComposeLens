// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type hostileCase struct {
	name  string
	slot  string
	value string
}

func hostileCorpus() []hostileCase {
	return []hostileCase{
		{name: "script-island-breakout", slot: "service-name", value: `</script><script>alert(1)</script>`},
		{name: "script-tag", slot: "effective", value: `<script>alert(1)</script>`},
		{name: "img-onerror", slot: "finding-target", value: `"><img onerror=alert(1)>`},
		{name: "svg-onload", slot: "finding-message", value: `<svg onload=alert(1)>`},
		{name: "javascript-url", slot: "effective", value: `javascript:alert(1)`},
		{name: "data-html-url", slot: "env-effective", value: `data:text/html,<script>alert(1)</script>`},
		{name: "vbscript-url", slot: "chain-source", value: `vbscript:msgbox(1)`},
		{name: "blob-url", slot: "label-message", value: `blob:https://evil.example/uuid`},
		{name: "protocol-relative", slot: "file-path", value: `//evil.example/x`},
		{name: "js-crlf-obfuscated", slot: "finding-name", value: "java\nscript:alert(1)"},
		{name: "style-breakout", slot: "diag-message", value: `</style><script>alert(1)</script>`},
		{name: "css-expression", slot: "diag-doc", value: `expression(alert(1))`},
		{name: "quote-onclick", slot: "row-internal", value: `"' onclick=alert(1) x='`},
		{name: "nul-script", slot: "reason", value: "<scr\x00ipt>alert(1)</script>"},
	}
}

func applyHostile(pkg Package, slot, value string) Package {
	eff := value
	switch slot {
	case "service-name":
		pkg.Source.Services[0].Name = value
	case "effective", "env-effective":
		pkg.Graph.Nodes[0].Effective = &eff
	case "finding-target":
		pkg.Check.Findings[0].Target = value
	case "finding-message":
		pkg.Check.Findings[0].Message = value
	case "finding-name":
		pkg.Check.Findings[0].Name = value
	case "chain-source":
		pkg.Graph.Nodes[0].ShadowChain[0].Source = value
	case "label-message":
		pkg.Check.Findings[0].Message = value
	case "file-path":
		pkg.Source.Files[0].Path = value
	case "diag-message":
		pkg.Diagnostics[0].Message = value
	case "diag-doc":
		pkg.Diagnostics[0].Doc = value
	case "row-internal":
		pkg.Differential.Rows[0].Internal = value
	case "reason":
		pkg.Graph.Nodes[0].Reason = value
	default:
		panic(slot)
	}
	return pkg
}

func TestHostileFixtureBattery(t *testing.T) {
	corpus := hostileCorpus()
	if len(corpus) < 12 {
		t.Fatalf("need >=12 vectors, got %d", len(corpus))
	}
	for _, tc := range corpus {
		t.Run(tc.name, func(t *testing.T) {
			pkg := applyHostile(interactivePackage(), tc.slot, tc.value)
			raw, err := Encode(pkg)
			if err != nil {
				t.Fatal(err)
			}
			page, err := HTML(raw)
			if err != nil {
				t.Fatal(err)
			}
			assertInert(t, page, tc.value)
		})
	}
}

func assertInert(t *testing.T, page []byte, original string) {
	t.Helper()
	if refs := RemoteRefs(page); len(refs) > 0 {
		t.Fatalf("remote refs: %v", refs)
	}
	if sinks := LiveSinks(page); len(sinks) > 0 {
		t.Fatalf("live sinks: %v", sinks)
	}
	if bytes.Count(page, []byte("</script>")) != LegitScriptCloseCount {
		t.Fatalf("island broken </script> count=%d", bytes.Count(page, []byte("</script>")))
	}
	if bytes.Contains(page, []byte("<script>alert")) {
		t.Fatal("live script tag")
	}
	if bytes.Contains(page, []byte("<img")) {
		t.Fatal("live img")
	}
	if bytes.Contains(page, []byte("<svg")) {
		t.Fatal("live svg")
	}
	if bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
		t.Fatal("innerHTML")
	}
	if !bytes.Contains(page, []byte(`Content-Security-Policy`)) || !bytes.Contains(page, []byte("default-src 'none'")) {
		t.Fatal("CSP missing")
	}
	island, err := DataIslandJSON(page)
	if err != nil {
		t.Fatal(err)
	}
	var round Package
	if err := json.Unmarshal(island, &round); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(original, "<") {
		if bytes.Contains(island, []byte("<script>")) || bytes.Contains(island, []byte("<img")) || bytes.Contains(island, []byte("<svg")) {
			t.Fatal("raw markup in island")
		}
		if !bytes.Contains(island, []byte(`\u003c`)) {
			t.Fatal("expected HTMLEscape \\u003c for data containing <")
		}
	}
}

func TestHostileJavascriptURLStaysText(t *testing.T) {
	pkg := applyHostile(interactivePackage(), "effective", "javascript:alert(1)")
	raw, err := Encode(pkg)
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	shell := page
	if isl := dataIsland(page); isl != nil {
		shell = bytes.Replace(page, isl, nil, 1)
	}
	if bytes.Contains(bytes.ToLower(shell), []byte("javascript:")) {
		t.Fatal("javascript: leaked into shell attributes")
	}
	if bytes.Contains(page, []byte(`href="javascript:`)) || bytes.Contains(page, []byte(`src="javascript:`)) {
		t.Fatal("javascript: sink")
	}
}
