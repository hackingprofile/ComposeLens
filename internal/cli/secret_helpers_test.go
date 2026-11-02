// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/report"
)

// Helpers for the secret-leak regression tests.

// decodedStrings returns every string (keys included) of a JSON document, of
// each JSON line in a text, and of an HTML report's data island, after JSON
// decoding, so an escaped copy of a value cannot hide from a search.
func decodedStrings(raw []byte) []string {
	var docs [][]byte
	trim := bytes.TrimSpace(raw)
	if json.Valid(trim) {
		docs = append(docs, trim)
	}
	if island, err := report.DataIslandJSON(raw); err == nil {
		docs = append(docs, island)
	}
	var out []string
	for _, d := range docs {
		var v any
		if err := json.Unmarshal(d, &v); err != nil {
			continue
		}
		walkJSONStrings(v, &out)
	}
	return out
}

func walkJSONStrings(v any, out *[]string) {
	switch x := v.(type) {
	case string:
		*out = append(*out, x)
	case map[string]any:
		for k, e := range x {
			*out = append(*out, k)
			walkJSONStrings(e, out)
		}
	case []any:
		for _, e := range x {
			walkJSONStrings(e, out)
		}
	}
}

// assertNoSecret fails when secret appears raw or in any decoded string of
// any of the given outputs (case-insensitive, as the guard compares).
func assertNoSecret(t *testing.T, label, secret string, outputs ...[]byte) {
	t.Helper()
	low := strings.ToLower(secret)
	for i, o := range outputs {
		if strings.Contains(strings.ToLower(string(o)), low) {
			t.Errorf("%s: secret present raw in output %d", label, i)
		}
		for _, s := range decodedStrings(o) {
			if strings.Contains(strings.ToLower(s), low) {
				t.Errorf("%s: secret present after decoding output %d", label, i)
				break
			}
		}
	}
}
