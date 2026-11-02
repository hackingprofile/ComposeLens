// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"strings"

	"composelens/internal/redact"
)

const minScanLen = 6

// MinScanLen is the shortest secret value (in bytes) the output guard can scan
// for reliably; a shorter collected secret makes output safety uncertain.
const MinScanLen = minScanLen

// Guard fail-closes if a collected secret would appear in output, or if a
// secret is too short to scan reliably. Callers must not write the buffer
// when this returns an error (CLI exit 4).
//
// A secret is searched in every representation ComposeLens emits: raw bytes,
// JSON string escaping (with and without HTML escaping, which is also the
// report's data island), HTML text escaping and GitHub workflow-command
// escaping. JSON documents and HTML data islands are additionally decoded
// and every decoded string is searched, so no escape form can hide a copy.
func Guard(output []byte, secrets []string) error {
	return GuardWithRevisions(output, secrets, nil)
}

// GuardWithRevisions also accepts public revisions identified in Compose
// fields. Known secret values and vendor patterns are still checked first.
func GuardWithRevisions(output []byte, secrets, revisions []string) error {
	if output == nil {
		return fmt.Errorf("output safety uncertain: empty writer buffer")
	}
	lowOut := bytes.ToLower(output)
	var decoded []string
	decodedReady := false
	for _, secret := range secrets {
		if secret == "" {
			continue
		}
		if len(secret) < minScanLen {
			return fmt.Errorf("output safety uncertain: secret value shorter than %d bytes cannot be scanned reliably", minScanLen)
		}
		for _, form := range representations(secret) {
			if bytes.Contains(output, []byte(form)) || bytes.Contains(lowOut, bytes.ToLower([]byte(form))) {
				return fmt.Errorf("output safety failed: a secret value would leak")
			}
		}
		if !decodedReady {
			decoded = decodedStrings(output)
			decodedReady = true
		}
		low := strings.ToLower(secret)
		for _, s := range decoded {
			if strings.Contains(strings.ToLower(s), low) {
				return fmt.Errorf("output safety failed: a secret value would leak")
			}
		}
	}
	// A recognized vendor token is never printed, whatever field carries it
	// (a path, version text or other metadata). Go JSON and HTML escaping leave
	// token characters unchanged, so the raw bytes are enough here.
	if redact.ContainsStrongToken(string(output)) {
		return fmt.Errorf("output safety failed: a recognized credential pattern would be printed")
	}
	// A value shaped like a generated credential (32+ letters and digits that
	// switch often, such as a hex or base64 key) is never printed even when no
	// rule classified it. Labelled digests and fingerprints are exempt.
	shapeText := string(output)
	for _, revision := range revisions {
		if redact.PublicRevision("GIT_COMMIT", revision) {
			re := regexp.MustCompile(`(^|[^A-Za-z0-9])` + regexp.QuoteMeta(revision) + `([^A-Za-z0-9]|$)`)
			shapeText = re.ReplaceAllString(shapeText, "${1}[revision]${2}")
		}
	}
	if redact.SecretShapedRun(shapeText) != "" {
		return fmt.Errorf("output safety failed: a secret-shaped value would be printed")
	}
	// Neutralize leftover C0/DEL controls in place (ANSI/ESC, CR, NUL). Length is
	// preserved so callers that write the same buffer after Guard stay aligned.
	// Newlines and tabs are kept so human reports remain readable. This does not
	// replace secret redaction; it only makes active content inert.
	neutralizeActiveControls(output)
	return nil
}

// representations lists the byte forms a secret takes in ComposeLens output.
func representations(secret string) []string {
	forms := []string{secret}
	add := func(s string) {
		for _, f := range forms {
			if f == s {
				return
			}
		}
		forms = append(forms, s)
	}
	add(jsonEscape(secret, true))
	add(jsonEscape(secret, false))
	add(html.EscapeString(secret))
	data := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(secret)
	add(data)
	add(strings.NewReplacer(":", "%3A", ",", "%2C").Replace(data))
	return forms
}

// jsonEscape returns the body of the JSON string literal for s.
func jsonEscape(s string, escapeHTML bool) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(escapeHTML)
	if err := enc.Encode(s); err != nil {
		return s
	}
	out := strings.TrimSuffix(b.String(), "\n")
	return strings.TrimSuffix(strings.TrimPrefix(out, `"`), `"`)
}

const islandOpen = `<script type="application/json"`

// decodedStrings returns every string (keys included) of the output when it
// is one JSON document, and of every JSON data island in an HTML document.
func decodedStrings(output []byte) []string {
	var docs [][]byte
	if trim := bytes.TrimSpace(output); len(trim) > 0 && (trim[0] == '{' || trim[0] == '[') && json.Valid(trim) {
		docs = append(docs, trim)
	}
	rest := output
	for {
		i := bytes.Index(rest, []byte(islandOpen))
		if i < 0 {
			break
		}
		rest = rest[i+len(islandOpen):]
		gt := bytes.IndexByte(rest, '>')
		if gt < 0 {
			break
		}
		rest = rest[gt+1:]
		end := bytes.Index(rest, []byte("</script>"))
		if end < 0 {
			break
		}
		docs = append(docs, rest[:end])
		rest = rest[end:]
	}
	var out []string
	for _, d := range docs {
		var v any
		if err := json.Unmarshal(d, &v); err != nil {
			continue
		}
		collectStrings(v, &out)
	}
	return out
}

func collectStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case map[string]any:
		for k, e := range x {
			*out = append(*out, k)
			collectStrings(e, out)
		}
	case []any:
		for _, e := range x {
			collectStrings(e, out)
		}
	}
}

func neutralizeActiveControls(output []byte) {
	for i, b := range output {
		if b == '\n' || b == '\t' {
			continue
		}
		if b < 0x20 || b == 0x7f {
			output[i] = '?'
		}
	}
}
