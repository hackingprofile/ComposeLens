// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"strings"

	"composelens/internal/check"
	"composelens/internal/exitcode"
)

// MapActionExit maps a completed check process status through the Action
// fail-on input. Usage/input/safety/internal/unsupported exits are unchanged.
// Default fail-on is "error", matching check's assertion gate. This does not
// alter check --json / --sarif / human exits.
func MapActionExit(checkExit int, r check.Result, failOn string) int {
	if checkExit != exitcode.OK && checkExit != exitcode.Assertion {
		return checkExit
	}
	switch strings.ToLower(strings.TrimSpace(failOn)) {
	case "", "error":
		return check.AssertionExit(r)
	case "never":
		return exitcode.OK
	case "warning":
		if hasUnwaivedAtLeast(r, check.SevWarning) {
			return exitcode.Assertion
		}
		return exitcode.OK
	case "info":
		if hasUnwaivedAtLeast(r, check.SevInfo) {
			return exitcode.Assertion
		}
		return exitcode.OK
	default:
		return check.AssertionExit(r)
	}
}

func hasUnwaivedAtLeast(r check.Result, gate string) bool {
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		if rank(f.Severity) >= rank(gate) {
			return true
		}
	}
	return false
}

func rank(sev string) int {
	switch sev {
	case check.SevError:
		return 3
	case check.SevWarning:
		return 2
	case check.SevInfo:
		return 1
	default:
		return 0
	}
}
