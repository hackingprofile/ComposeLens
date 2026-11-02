// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"strings"

	"composelens/internal/redact"

	"gopkg.in/yaml.v3"
)

const minGuardFragment = 6

// SecretFragments returns scannable secret material from a policy file.
// The whole file is never treated as one fragment. Short fragments are
// omitted so Guard can still emit a typed invalid-policy diagnostic
// instead of fail-closed.
func SecretFragments(raw []byte) []string {
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
		if v == "" || !redact.LooksLikeSecret(v) {
			return
		}
		for _, f := range redact.SecretFragments(v) {
			addFrag(f)
		}
	}
	addKeyed := func(key, val string) {
		if redact.LooksLikeSecret(key) {
			addSecretValue(key)
		}
		if redact.IsSecretKey(key) && val != "" {
			for _, f := range redact.SecretFragments(val) {
				addFrag(f)
			}
			return
		}
		addSecretValue(val)
	}
	walkSecrets(bestEffortTree(raw), "", addKeyed)
	for _, tok := range strings.FieldsFunc(string(raw), isPolicySep) {
		addSecretValue(tok)
	}
	return out
}

func isPolicySep(r rune) bool {
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

func walkSecrets(v any, parentKey string, add func(key, val string)) {
	switch t := v.(type) {
	case map[string]any:
		for k, val := range t {
			add(k, "")
			walkSecrets(val, k, add)
		}
	case []any:
		for _, item := range t {
			walkSecrets(item, parentKey, add)
		}
	case string:
		add(parentKey, t)
	}
}
