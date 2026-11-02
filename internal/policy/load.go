// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"composelens/internal/safety"
)

var nowUTC = func() time.Time { return time.Now().UTC() }

func Load(path string, budget ...*safety.Budget) (*Document, []byte, error) {
	raw, err := safety.ReadAtMost(path, safety.MaxFileBytes)
	if err != nil {
		if errors.Is(err, safety.ErrInputTooLarge) {
			return nil, nil, &Error{Kind: KindTooLarge, Message: "policy file exceeds the byte bound"}
		}
		return nil, nil, &Error{Kind: KindMissingFile, Message: "policy file is not readable"}
	}
	if err := safety.Optional(budget).ChargePath(path, len(raw)); err != nil {
		return nil, nil, err
	}
	doc, err := Parse(raw)
	return doc, raw, err
}

func Parse(raw []byte) (*Document, error) {
	if !utf8.Valid(raw) {
		return nil, &Error{Kind: KindEncoding, Message: "policy file is not valid UTF-8"}
	}
	trim := bytes.TrimSpace(raw)
	if len(trim) == 0 {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is empty"}
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
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	return validateTop(top)
}

func validateTop(top map[string]any) (*Document, error) {
	schema, ok := asString(top["schema"])
	if !ok || strings.TrimSpace(schema) == "" {
		return nil, &Error{Kind: KindMissingSchema, Message: "missing schema"}
	}
	if schema != Schema {
		return nil, &Error{Kind: KindUnknownSchema, Message: "unknown schema " + label(schema)}
	}
	for _, k := range sortedKeys(top) {
		switch k {
		case "schema", "rules", "exceptions", "gate":
		default:
			return nil, &Error{Kind: KindUnknownField, Message: "unknown field " + label(k)}
		}
	}
	doc := &Document{
		Schema:     Schema,
		Rules:      map[string]Rule{},
		Exceptions: map[string]Exception{},
	}
	if v, exists := top["gate"]; exists && v != nil {
		s, ok := asString(v)
		if !ok || strings.TrimSpace(s) == "" {
			return nil, &Error{Kind: KindInvalidRule, Message: "gate must be a string"}
		}
		if _, ok := knownSeverities[s]; !ok {
			return nil, &Error{Kind: KindInvalidRule, Message: "unknown gate " + label(s)}
		}
		doc.Gate = s
	}
	if v, exists := top["rules"]; exists && v != nil {
		if err := parseRules(doc, v); err != nil {
			return nil, err
		}
	}
	if v, exists := top["exceptions"]; exists && v != nil {
		if err := parseExceptions(doc, v); err != nil {
			return nil, err
		}
	}
	return doc, nil
}

func parseRules(doc *Document, v any) error {
	switch t := v.(type) {
	case []any:
		for i, item := range t {
			m, ok := item.(map[string]any)
			if !ok {
				return &Error{Kind: KindMalformed, Message: "rules entries must be objects"}
			}
			id, spec, err := parseRuleObj(m, true)
			if err != nil {
				return err
			}
			if id == "" {
				return &Error{Kind: KindInvalidRule, Message: fmt.Sprintf("rules[%d] missing id", i)}
			}
			if _, ok := doc.Rules[id]; ok {
				return &Error{Kind: KindDuplicateRule, Message: "duplicate rule " + label(id)}
			}
			doc.Rules[id] = spec
		}
	case map[string]any:
		for _, id := range sortedKeys(t) {
			item := t[id]
			if !KnownRule(id) {
				return &Error{Kind: KindUnknownRule, Message: "unknown rule id " + label(id)}
			}
			m, ok := item.(map[string]any)
			if !ok {
				return &Error{Kind: KindMalformed, Message: "rule " + label(id) + " must be an object"}
			}
			if rawID, has := m["id"]; has {
				s, ok := asString(rawID)
				if !ok || s != id {
					return &Error{Kind: KindInvalidRule, Message: "rule id mismatch for " + label(id)}
				}
			}
			_, spec, err := parseRuleObj(m, false)
			if err != nil {
				return err
			}
			if _, ok := doc.Rules[id]; ok {
				return &Error{Kind: KindDuplicateRule, Message: "duplicate rule " + label(id)}
			}
			doc.Rules[id] = spec
		}
	default:
		return &Error{Kind: KindMalformed, Message: "rules must be a list or map"}
	}
	return nil
}

func parseRuleObj(m map[string]any, requireID bool) (string, Rule, error) {
	var spec Rule
	var id string
	for _, k := range sortedKeys(m) {
		val := m[k]
		switch k {
		case "id":
			s, ok := asString(val)
			if !ok || strings.TrimSpace(s) == "" {
				return "", spec, &Error{Kind: KindInvalidRule, Message: "rule id must be a string"}
			}
			id = s
		case "enabled":
			b, ok := val.(bool)
			if !ok {
				return "", spec, &Error{Kind: KindInvalidRule, Message: "enabled must be a boolean"}
			}
			spec.Enabled = &b
		case "severity":
			s, ok := asString(val)
			if !ok || strings.TrimSpace(s) == "" {
				return "", spec, &Error{Kind: KindInvalidRule, Message: "severity must be a string"}
			}
			if _, ok := knownSeverities[s]; !ok {
				return "", spec, &Error{Kind: KindInvalidRule, Message: "unknown severity " + label(s)}
			}
			spec.Severity = s
		default:
			return "", spec, &Error{Kind: KindUnknownField, Message: "unknown field " + label(k)}
		}
	}
	if requireID {
		if id == "" {
			return "", spec, &Error{Kind: KindInvalidRule, Message: "rule missing id"}
		}
		if !KnownRule(id) {
			return "", spec, &Error{Kind: KindUnknownRule, Message: "unknown rule id " + label(id)}
		}
	}
	return id, spec, nil
}

func parseExceptions(doc *Document, v any) error {
	list, ok := v.([]any)
	if !ok {
		return &Error{Kind: KindMalformed, Message: "exceptions must be a list"}
	}
	today := dateOnly(nowUTC())
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			return &Error{Kind: KindMalformed, Message: "exception entries must be objects"}
		}
		var rule, expires string
		for _, k := range sortedKeys(m) {
			val := m[k]
			switch k {
			case "rule":
				s, ok := asString(val)
				if !ok || strings.TrimSpace(s) == "" {
					return &Error{Kind: KindInvalidRule, Message: "exception rule must be a string"}
				}
				rule = s
			case "expires":
				s, ok := dateString(val)
				if !ok || strings.TrimSpace(s) == "" {
					return &Error{Kind: KindExceptionDate, Message: "exception expires must be a date string"}
				}
				expires = s
			default:
				return &Error{Kind: KindUnknownField, Message: "unknown field " + label(k)}
			}
		}
		if rule == "" {
			return &Error{Kind: KindInvalidRule, Message: "exception missing rule"}
		}
		if !KnownRule(rule) {
			return &Error{Kind: KindUnknownRule, Message: "unknown rule id " + label(rule)}
		}
		if expires == "" {
			return &Error{Kind: KindExceptionDate, Message: "exception missing expires"}
		}
		day, err := parseDate(expires)
		if err != nil {
			return &Error{Kind: KindExceptionDate, Message: "exception expires is invalid"}
		}
		if !day.After(today) {
			return &Error{Kind: KindExceptionDate, Message: "exception expires must be a future date"}
		}
		if _, ok := doc.Exceptions[rule]; ok {
			return &Error{Kind: KindDuplicateExcept, Message: "duplicate exception for " + label(rule)}
		}
		doc.Exceptions[rule] = Exception{Rule: rule, Expires: day}
	}
	return nil
}

func parseDate(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return dateOnly(t), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return dateOnly(t.UTC()), nil
	}
	return time.Time{}, fmt.Errorf("invalid date")
}

func dateOnly(t time.Time) time.Time {
	u := t.UTC()
	return time.Date(u.Year(), u.Month(), u.Day(), 0, 0, 0, 0, time.UTC)
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func dateString(v any) (string, bool) {
	if s, ok := asString(v); ok {
		return s, true
	}
	if t, ok := v.(time.Time); ok {
		return t.UTC().Format("2006-01-02"), true
	}
	return "", false
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
