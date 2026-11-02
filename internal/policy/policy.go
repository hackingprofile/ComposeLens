// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"strings"
	"time"

	"composelens/internal/redact"
)

const (
	Schema      = "composelens.policy.v0"
	DefaultGate = "error"

	KindMissingFile     = "missing-file"
	KindMalformed       = "malformed"
	KindMissingSchema   = "missing-schema"
	KindUnknownSchema   = "unknown-schema"
	KindUnknownField    = "unknown-field"
	KindUnknownRule     = "unknown-rule"
	KindInvalidRule     = "invalid-rule"
	KindExceptionDate   = "exception-date"
	KindDuplicateRule   = "duplicate-rule"
	KindDuplicateExcept = "duplicate-exception"
	KindDuplicateField  = "duplicate-field"
	KindTooLarge        = "too-large"
	KindEncoding        = "invalid-encoding"
	KindTooDeep         = "too-deep"
	KindTooManyNodes    = "too-many-nodes"
	KindUnsupported     = "unsupported-construct"
	KindMultiDoc        = "multiple-documents"
	KindTrailing        = "trailing-content"
)

var knownRules = map[string]struct{}{
	"CHK01": {},
	"CHK02": {},
	"CHK03": {},
	"CHK04": {},
	"CHK05": {},
	"CHK06": {},
}

var knownSeverities = map[string]struct{}{
	"error":   {},
	"warning": {},
	"info":    {},
}

// Document is a schema-validated policy overlay on the fixed check ruleset.
type Document struct {
	Schema     string
	Gate       string
	Rules      map[string]Rule
	Exceptions map[string]Exception
}

type Rule struct {
	Enabled  *bool
	Severity string
}

type Exception struct {
	Rule    string
	Expires time.Time
}

type Error struct {
	Kind    string
	Message string
}

func (e *Error) Error() string {
	if e == nil {
		return "policy: invalid"
	}
	if e.Kind == "" {
		return "policy: " + e.Message
	}
	return "policy: " + e.Kind + ": " + e.Message
}

func KnownRule(id string) bool {
	_, ok := knownRules[id]
	return ok
}

func (d *Document) Enabled(id string) bool {
	if d == nil {
		return true
	}
	r, ok := d.Rules[id]
	if !ok || r.Enabled == nil {
		return true
	}
	return *r.Enabled
}

func (d *Document) Severity(id, def string) string {
	if d == nil {
		return def
	}
	r, ok := d.Rules[id]
	if !ok || r.Severity == "" {
		return def
	}
	return r.Severity
}

func (d *Document) GateLevel() string {
	if d == nil || strings.TrimSpace(d.Gate) == "" {
		return DefaultGate
	}
	return d.Gate
}

func (d *Document) Waived(id string) bool {
	if d == nil {
		return false
	}
	ex, ok := d.Exceptions[id]
	if !ok {
		return false
	}
	now := dateOnly(nowUTC())
	return now.Before(ex.Expires)
}

// SetNowUTC replaces the clock used for load-time expiry checks and waiver execution.
// Pass nil to restore time.Now().UTC. Tests must restore the previous clock.
func SetNowUTC(fn func() time.Time) {
	if fn == nil {
		nowUTC = func() time.Time { return time.Now().UTC() }
		return
	}
	nowUTC = fn
}

func label(s string) string {
	return redact.DiagnosticLabel(s)
}
