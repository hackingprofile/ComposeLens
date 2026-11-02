// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"encoding/json"
	"strings"

	"gopkg.in/yaml.v3"
)

const minGuardFragment = 6

// ConfigSecretFragments returns scannable secret material from a redaction
// config file so diagnostics can be Guard-checked. The whole file is never one
// fragment. Overlay matching is not used (defaults only) so a half-applied
// config cannot hide a leak from the guard.
func ConfigSecretFragments(raw []byte) []string {
	if len(raw) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	var out []string
	addFrag := func(f string) {
		if len(f) < minGuardFragment {
			return
		}
		if _, ok := seen[f]; ok {
			return
		}
		seen[f] = struct{}{}
		out = append(out, f)
	}
	addSecretValue := func(v string) {
		if v == "" || !looksLikeSecretDefault(v) {
			return
		}
		for _, f := range SecretFragments(v) {
			addFrag(f)
		}
	}
	walkConfigSecrets(bestEffortTree(raw), addSecretValue)
	for _, tok := range strings.FieldsFunc(string(raw), isConfigSep) {
		addSecretValue(tok)
	}
	return out
}

func isConfigSep(r rune) bool {
	if r == ':' || r == '"' || r == '\'' || r == '{' || r == '}' || r == '[' || r == ']' || r == ',' || r == '=' {
		return true
	}
	return r == ' ' || r == '\t' || r == '\n' || r == '\r'
}

func bestEffortTree(raw []byte) any {
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return nil
	}
	var top any
	if trim[0] == '{' {
		if err := json.Unmarshal(trim, &top); err == nil {
			return top
		}
		return nil
	}
	if err := yaml.Unmarshal(trim, &top); err == nil {
		return top
	}
	return nil
}

func walkConfigSecrets(v any, add func(string)) {
	switch t := v.(type) {
	case map[string]any:
		for _, val := range t {
			walkConfigSecrets(val, add)
		}
	case []any:
		for _, item := range t {
			walkConfigSecrets(item, add)
		}
	case string:
		add(t)
	}
}
