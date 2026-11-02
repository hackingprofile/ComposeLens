// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"testing"
)

func TestGuardDetectsLeak(t *testing.T) {
	err := Guard([]byte("hello super-secret-token-value world"), []string{"super-secret-token-value"})
	if err == nil {
		t.Fatal("expected leak to fail closed")
	}
}

func TestGuardClean(t *testing.T) {
	err := Guard([]byte(`{"fingerprint":"hmac-sha256:abcd"}`), []string{"super-secret-token-value"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGuardShortSecretUncertain(t *testing.T) {
	err := Guard([]byte("ok"), []string{"ab"})
	if err == nil {
		t.Fatal("short secrets must fail closed as uncertain")
	}
	if want := fmt.Sprintf("shorter than %d bytes", minScanLen); !strings.Contains(err.Error(), want) {
		t.Fatalf("the rule counts bytes; message %q lacks %q", err, want)
	}
}

func TestGuardNeutralizesANSIAndCR(t *testing.T) {
	raw := []byte("value=\x1b[31mRED\x1b[0m\r\nnext")
	if err := Guard(raw, []string{"super-secret-token-value"}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte{0x1b}) || bytes.Contains(raw, []byte{'\r'}) {
		t.Fatalf("controls still present: %q", raw)
	}
	if !bytes.Contains(raw, []byte("?[31mRED?[0m?\nnext")) {
		t.Fatalf("got %q", raw)
	}
}

func TestGuardNeutralizeDoesNotHideSecret(t *testing.T) {
	raw := []byte("token=super-secret-token-value")
	err := Guard(raw, []string{"super-secret-token-value"})
	if err == nil {
		t.Fatal("expected leak to fail closed before neutralize")
	}
}

func TestParseErrorTypedAndSecretSafe(t *testing.T) {
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	err := NewParseError(CodeMalformed, "compose.yaml", "saw "+probe)
	if CodeOf(err) != CodeMalformed {
		t.Fatalf("code=%s", CodeOf(err))
	}
	if strings.Contains(err.Error(), probe) {
		t.Fatalf("leaked %s", err)
	}
	if err := Guard([]byte(err.Error()), []string{probe}); err != nil {
		t.Fatal(err)
	}
}

// The guard must recognize a secret after the escaping that JSON,
// the HTML data island and GitHub workflow commands apply, not only its raw
// bytes.
func TestGuardCatchesSerializedSecretRepresentations(t *testing.T) {
	secrets := []string{
		`solar-"quoted"-value`,
		"solar-first\nsecond",
		`solar-back\value`,
		"solar-<tag>&amp-value",
		"solar-line value",
		"solar-100%-value\r\n",
	}
	for _, s := range secrets {
		forms := map[string][]byte{}
		js, _ := json.Marshal(map[string]string{"copy": s})
		forms["json"] = js
		var noHTML bytes.Buffer
		enc := json.NewEncoder(&noHTML)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]string{"copy": s})
		forms["json-no-html-escape"] = noHTML.Bytes()
		var island bytes.Buffer
		json.HTMLEscape(&island, noHTML.Bytes())
		forms["html-island"] = island.Bytes()
		forms["html-text"] = []byte("<td>" + html.EscapeString(s) + "</td>")
		ann := strings.NewReplacer("%", "%25", "\r", "%0D", "\n", "%0A").Replace(s)
		forms["workflow-command"] = []byte("::warning file=compose.yaml::" + ann)
		uni := strings.Builder{}
		for _, r := range s {
			fmt.Fprintf(&uni, `\u%04x`, r)
		}
		forms["json-unicode-escapes"] = []byte(`{"copy":"` + uni.String() + `"}`)
		for name, out := range forms {
			if err := Guard(append([]byte(nil), out...), []string{s}); err == nil {
				t.Errorf("%q in %s form was not caught: %s", s, name, out)
			}
		}
	}
	if err := Guard([]byte(`{"copy":"public-value"}`), []string{`solar-"quoted"-value`}); err != nil {
		t.Fatalf("clean output refused: %v", err)
	}
}

// Output that still carries a recognized vendor token (in a path,
// version or other metadata) is refused, raw or JSON-escaped.
func TestGuardRefusesRecognizedTokenInOutput(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a", 30)
	for _, out := range []string{
		`{"projectDirectory":"C:\fx\path-` + tok + `"}`,
		"Engine: " + tok + "\n",
	} {
		if err := Guard([]byte(out), nil); err == nil {
			t.Errorf("token in %q not refused", out)
		}
	}
	if err := Guard([]byte(`{"projectDirectory":"C:\fx\ordinary"}`), nil); err != nil {
		t.Fatalf("ordinary output refused: %v", err)
	}
}
