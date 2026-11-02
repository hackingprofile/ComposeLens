// SPDX-License-Identifier: Apache-2.0

package check

import "composelens/internal/policy"

const PolicyDisclaimer = "schema-validated policy overlay on the fixed ruleset — not a general policy engine"
const PolicyRuleset = "policy-v0"

// ApplyPolicy overlays a validated policy on Evaluate findings.
// Disabled rules are dropped. Waived findings are kept with Waived set and
// are excluded from the severity gate while the exception is unexpired.
func ApplyPolicy(r Result, doc *policy.Document) Result {
	r.Gate = policy.DefaultGate
	if doc == nil {
		return r
	}
	r.Gate = doc.GateLevel()
	out := make([]Finding, 0, len(r.Findings))
	for _, f := range r.Findings {
		if !doc.Enabled(f.ID) {
			continue
		}
		f.Severity = doc.Severity(f.ID, f.Severity)
		if doc.Waived(f.ID) {
			f.Waived = true
			if ex, ok := doc.Exceptions[f.ID]; ok && !ex.Expires.IsZero() {
				f.WaiverExpires = ex.Expires.UTC().Format("2006-01-02")
			}
		}
		out = append(out, f)
	}
	return Result{
		Findings:     out,
		Evidence:     r.Evidence,
		Certainty:    r.Certainty,
		PolicySchema: doc.Schema,
		Gate:         r.Gate,
		sourceBase:   r.sourceBase,
	}
}
