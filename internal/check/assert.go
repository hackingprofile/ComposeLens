// SPDX-License-Identifier: Apache-2.0

package check

import "composelens/internal/exitcode"

func severityRank(sev string) int {
	switch sev {
	case SevError:
		return 3
	case SevWarning:
		return 2
	case SevInfo:
		return 1
	default:
		return 0
	}
}

func meetsGate(sev, gate string) bool {
	if gate == "" {
		gate = SevError
	}
	return severityRank(sev) >= severityRank(gate)
}

// AssertionExit is the check process status after a completed report.
// Gating (non-waived) findings at or above the gate severity yield exitcode.Assertion.
func AssertionExit(r Result) int {
	gate := r.Gate
	if gate == "" {
		gate = SevError
	}
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		if meetsGate(f.Severity, gate) {
			return exitcode.Assertion
		}
	}
	return exitcode.OK
}
