// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	KindMissingFile    = "missing-file"
	KindMalformed      = "malformed"
	KindMissingSchema  = "missing-schema"
	KindUnknownSchema  = "unknown-schema"
	KindUnknownField   = "unknown-field"
	KindInvalid        = "invalid"
	KindTooLarge       = "too-large"
	KindEncoding       = "invalid-encoding"
	KindTooDeep        = "too-deep"
	KindTooManyNodes   = "too-many-nodes"
	KindUnsupported    = "unsupported-construct"
	KindMultiDoc       = "multiple-documents"
	KindTrailing       = "trailing-content"
	KindDuplicateField = "duplicate-field"
)

type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return "redact: invalid"
	}
	if e.Kind == "" {
		return "redact: " + e.Message
	}
	return "redact: " + e.Kind + ": " + e.Message
}

func Parse(raw []byte) (*Config, error) {
	if !utf8.Valid(raw) {
		return nil, &Error{Kind: KindEncoding, Message: "redaction config is not valid UTF-8"}
	}
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return nil, &Error{Kind: KindMalformed, Message: "redaction config is empty"}
	}
	var top map[string]any
	var err error
	if trim[0] == '{' {
		top, err = decodeJSONObject(trim)
	} else {
		top, err = decodeYAMLMapping(trim)
	}
	if err != nil {
		return nil, err
	}
	if top == nil {
		return nil, &Error{Kind: KindMalformed, Message: "redaction config is malformed"}
	}
	return validateTop(top)
}

func validateTop(top map[string]any) (*Config, error) {
	schema, ok := asString(top["schema"])
	if !ok || strings.TrimSpace(schema) == "" {
		return nil, &Error{Kind: KindMissingSchema, Message: "missing schema"}
	}
	if schema != Schema {
		return nil, &Error{Kind: KindUnknownSchema, Message: "unknown schema " + label(schema)}
	}
	for _, k := range sortedKeys(top) {
		switch k {
		case "schema", "display", "secretKeys", "secretValues", "allowKeys", "allowValues":
		default:
			return nil, &Error{Kind: KindUnknownField, Message: "unknown field " + label(k)}
		}
	}
	cfg := &Config{
		Schema:    Schema,
		Display:   DisplayFingerprint,
		allowKeys: map[string]struct{}{},
		allowVals: map[string]struct{}{},
	}
	if v, exists := top["display"]; exists && v != nil {
		s, ok := asString(v)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, &Error{Kind: KindInvalid, Message: "display must be a string"}
		}
		switch DisplayMode(s) {
		case DisplayFingerprint, DisplayRedacted:
			cfg.Display = DisplayMode(s)
		default:
			return nil, &Error{Kind: KindInvalid, Message: "unknown display " + label(s)}
		}
	}
	keys, err := stringList(top, "secretKeys")
	if err != nil {
		return nil, err
	}
	for _, p := range keys {
		re, err := compileAddedPattern(p, true)
		if err != nil {
			return nil, err
		}
		cfg.extraKeys = append(cfg.extraKeys, re)
	}
	vals, err := stringList(top, "secretValues")
	if err != nil {
		return nil, err
	}
	for _, p := range vals {
		re, err := compileAddedPattern(p, false)
		if err != nil {
			return nil, err
		}
		cfg.extraValues = append(cfg.extraValues, re)
	}
	allowK, err := stringList(top, "allowKeys")
	if err != nil {
		return nil, err
	}
	for _, k := range allowK {
		if err := rejectBlanketAllow(k); err != nil {
			return nil, err
		}
		if looksLikeSecretDefault(k) {
			return nil, secretShapedErr("allowKeys")
		}
		nk := NormalizeKey(k)
		if nk == "" {
			return nil, &Error{Kind: KindInvalid, Message: "allowKeys entry is empty"}
		}
		if _, ok := cfg.allowKeys[nk]; ok {
			return nil, &Error{Kind: KindInvalid, Message: "duplicate allowKeys entry"}
		}
		cfg.allowKeys[nk] = struct{}{}
	}
	allowV, err := stringList(top, "allowValues")
	if err != nil {
		return nil, err
	}
	for _, v := range allowV {
		if err := rejectBlanketAllow(v); err != nil {
			return nil, err
		}
		if _, ok := cfg.allowVals[v]; ok {
			return nil, &Error{Kind: KindInvalid, Message: "duplicate allowValues entry"}
		}
		cfg.allowVals[v] = struct{}{}
	}
	return cfg, nil
}

func stringList(top map[string]any, field string) ([]string, error) {
	v, exists := top[field]
	if !exists || v == nil {
		return nil, nil
	}
	list, ok := v.([]any)
	if !ok {
		return nil, &Error{Kind: KindMalformed, Message: field + " must be a list"}
	}
	if len(list) > maxListEntries {
		return nil, &Error{Kind: KindInvalid, Message: field + " exceeds the entry bound"}
	}
	out := make([]string, 0, len(list))
	for _, item := range list {
		s, ok := asString(item)
		if !ok {
			return nil, &Error{Kind: KindInvalid, Message: field + " entries must be strings"}
		}
		s = strings.TrimSpace(s)
		if s == "" {
			return nil, &Error{Kind: KindInvalid, Message: field + " entry is empty"}
		}
		if len(s) > maxPatternBytes {
			return nil, &Error{Kind: KindInvalid, Message: field + " entry exceeds the length bound"}
		}
		out = append(out, s)
	}
	return out, nil
}

func compileAddedPattern(p string, key bool) (*regexp.Regexp, error) {
	if looksLikeSecretDefault(p) {
		return nil, secretShapedErr("pattern")
	}
	if isBlanketPattern(p) {
		return nil, &Error{Kind: KindInvalid, Message: "blanket pattern is not allowed"}
	}
	expr := p
	if !hasRegexMeta(p) {
		expr = "^" + regexp.QuoteMeta(NormalizeKey(p)) + "$"
		if !key {
			expr = "^" + regexp.QuoteMeta(p) + "$"
		}
	} else if key {
		expr = p
	}
	re, err := regexp.Compile(expr)
	if err != nil {
		return nil, &Error{Kind: KindInvalid, Message: "pattern is not a valid regular expression"}
	}
	if re.MatchString("") && re.MatchString("x") && re.MatchString("composelens-allowlist-probe") {
		return nil, &Error{Kind: KindInvalid, Message: "blanket pattern is not allowed"}
	}
	return re, nil
}

func rejectBlanketAllow(s string) error {
	if isBlanketPattern(s) {
		return &Error{Kind: KindInvalid, Message: "allowlist entry must be specific"}
	}
	return nil
}

func isBlanketPattern(s string) bool {
	switch strings.TrimSpace(s) {
	case "*", ".*", ".+", "^.*$", "^.*", ".*$", "(?s).*", `(?s)^.*$`, `[\s\S]*`, `^[\s\S]*$`:
		return true
	}
	return false
}

func hasRegexMeta(s string) bool {
	return strings.ContainsAny(s, `^$.*+?[](){}|\`)
}

func secretShapedErr(where string) error {
	return &Error{Kind: KindInvalid, Message: where + " must be a pattern or name, not a secret-shaped value"}
}

func label(s string) string {
	return DiagnosticLabel(s)
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
