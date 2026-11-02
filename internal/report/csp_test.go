// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/safety"
)

func TestHTMLCSPHashPinned(t *testing.T) {
	raw, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	var escaped bytes.Buffer
	json.HTMLEscape(&escaped, bytes.TrimSpace(raw))
	want := cspPolicy(cspSHA256([]byte(htmlCSS)), cspSHA256([]byte(htmlBoot)), cspSHA256(escaped.Bytes()))
	if !bytes.Contains(page, []byte(`<meta http-equiv="Content-Security-Policy" content="`+want+`"`)) {
		t.Fatal("CSP meta missing or hash mismatch")
	}
	csp := want
	need := []string{
		"default-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"img-src 'none'",
		"script-src-attr 'none'",
	}
	for _, s := range need {
		if !strings.Contains(csp, s) {
			t.Fatalf("csp missing %s", s)
		}
	}
	for _, bad := range []string{"unsafe-eval", "http://", "https://", "ws://", "wss://", "unsafe-inline"} {
		if strings.Contains(csp, bad) {
			t.Fatalf("csp admits %s", bad)
		}
	}
}

func TestHTMLNoLiveSinksAndTrustedSkip(t *testing.T) {
	raw, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	page, err := HTML(raw)
	if err != nil {
		t.Fatal(err)
	}
	if sinks := LiveSinks(page); len(sinks) > 0 {
		t.Fatalf("sinks: %v", sinks)
	}
	if !bytes.Contains(page, []byte(`href="#main"`)) {
		t.Fatal("skip href")
	}
	if bytes.Count(page, []byte("</script>")) != LegitScriptCloseCount {
		t.Fatalf("</script> count=%d", bytes.Count(page, []byte("</script>")))
	}
	if bytes.Contains(bytes.ToLower(page), []byte("innerhtml")) {
		t.Fatal("innerHTML")
	}
}

func TestHTMLOutputTooLarge(t *testing.T) {
	pkg := interactivePackage()
	blob := strings.Repeat("X", 90_000)
	base := pkg.Graph.Nodes[0]
	for i := 0; i < 55; i++ {
		n := base
		n.Target = blob
		pkg.Graph.Nodes = append(pkg.Graph.Nodes, n)
	}
	raw, err := Encode(pkg)
	if err != nil {
		t.Fatal(err)
	}
	_, err = HTML(raw)
	if err == nil || !safety.IsResourceBound(err) || safety.CodeOf(err) != safety.CodeTotalTooLarge {
		t.Fatalf("want total-too-large, got %v", err)
	}
	normal, err := Encode(interactivePackage())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := HTML(normal); err != nil {
		t.Fatalf("normal report: %v", err)
	}
}

func TestDangerousScheme(t *testing.T) {
	yes := []string{
		"javascript:alert(1)",
		"  JAVA\nSCRIPT:alert(1)",
		"vbscript:msgbox",
		"data:text/html,<script>alert(1)</script>",
		"blob:https://evil",
		"//evil.example/x",
		"https://evil.example/",
	}
	for _, s := range yes {
		if !DangerousScheme(s) {
			t.Fatalf("want dangerous %q", s)
		}
	}
	if DangerousScheme("#main") || DangerousScheme("docs/check.md") || DangerousScheme("alpine") {
		t.Fatal("trusted/inert values flagged")
	}
}
