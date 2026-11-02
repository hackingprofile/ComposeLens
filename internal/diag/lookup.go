// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"errors"

	"composelens/internal/exitcode"
	"composelens/internal/policy"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

// LookupError maps a typed error to its catalog entry.
func LookupError(err error) (Entry, bool) {
	if err == nil {
		return Entry{}, false
	}
	var pe *policy.Error
	if errors.As(err, &pe) && pe != nil && pe.Kind != "" {
		return LookupID("policy." + pe.Kind)
	}
	var re *redact.Error
	if errors.As(err, &re) && re != nil && re.Kind != "" {
		return LookupID("redact." + re.Kind)
	}
	var se *safety.ParseError
	if errors.As(err, &se) && se != nil && se.Code != "" {
		return LookupID("safety." + string(se.Code))
	}
	return Entry{}, false
}

// LookupExit maps a process exit code to a catalog entry when no typed kind applies.
func LookupExit(code int) (Entry, bool) {
	switch code {
	case exitcode.Internal:
		return LookupID("exit.internal")
	case exitcode.Usage:
		return LookupID("cli.usage")
	case exitcode.Input:
		return LookupID("exit.input")
	case exitcode.Safety:
		return LookupID("exit.safety")
	case exitcode.Unsupported:
		return LookupID("exit.unsupported")
	case exitcode.Assertion:
		return LookupID("exit.assertion")
	default:
		return Entry{}, false
	}
}

// Resolve prefers a typed kind, then the exit-code class.
func Resolve(err error, code int) (Entry, bool) {
	if ent, ok := LookupError(err); ok {
		return ent, true
	}
	return LookupExit(code)
}
