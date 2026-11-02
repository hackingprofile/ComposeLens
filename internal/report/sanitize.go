// SPDX-License-Identifier: Apache-2.0

package report

import (
	"bytes"
	"regexp"
	"strings"
	"unicode"
)

// TrustedHRef is the only href the report may emit (skip link). It is not
// derived from package data.
const TrustedHRef = "#main"

var (
	attrSink    = regexp.MustCompile(`(?i)\s(?:href|src|action|formaction|xlink:href)\s*=\s*['"]([^'"]*)['"]`)
	onAttr      = regexp.MustCompile(`(?i)<[a-z][a-z0-9:-]*\b[^>]*\son[a-z]+\s*=`)
	stripBlocks = regexp.MustCompile(`(?is)<script\b[^>]*>.*?</script>|<style\b[^>]*>.*?</style>`)
)

// DangerousScheme reports whether s would be unsafe as a URL sink even after
// whitespace/CRLF/NUL stripping. Used to classify hostile fixtures; the
// renderer never assigns data values to href/src/on*.
func DangerousScheme(s string) bool {
	t := stripURLNoise(s)
	if t == "" {
		return false
	}
	for _, p := range []string{"javascript:", "vbscript:", "data:", "blob:"} {
		if strings.HasPrefix(t, p) {
			return true
		}
	}
	if strings.HasPrefix(t, "//") {
		return true
	}
	if strings.HasPrefix(t, "http:") || strings.HasPrefix(t, "https:") {
		return true
	}
	return false
}

func stripURLNoise(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range strings.ToLower(s) {
		if r == 0 || unicode.IsSpace(r) {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// LiveSinks reports attribute sinks in the HTML shell (data island excluded).
// The skip-link href="#main" is the only allowed href.
func LiveSinks(html []byte) []string {
	island := dataIsland(html)
	shell := html
	if island != nil {
		shell = bytes.Replace(html, island, nil, 1)
	}
	chrome := stripBlocks.ReplaceAll(shell, nil)
	var hits []string
	seen := map[string]struct{}{}
	add := func(s string) {
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		hits = append(hits, s)
	}
	for _, m := range attrSink.FindAllSubmatch(chrome, -1) {
		val := string(m[1])
		if strings.EqualFold(string(m[0]), "") {
			continue
		}
		attr := strings.ToLower(string(m[0]))
		if strings.Contains(attr, "href") && val == TrustedHRef {
			continue
		}
		add(strings.TrimSpace(string(m[0])))
	}
	if onAttr.Find(chrome) != nil {
		add("on*=event-handler")
	}
	low := bytes.ToLower(chrome)
	for _, n := range []string{"javascript:", "vbscript:", "data:text/html", "blob:"} {
		if bytes.Contains(low, []byte(n)) {
			add(n)
		}
	}
	return hits
}

// LegitScriptCloseCount is the number of </script> tags the shell itself emits
// (JSON island close + controller script close).
const LegitScriptCloseCount = 2
