// SPDX-License-Identifier: Apache-2.0

package check

import (
	"bytes"
	"encoding/json"
	"fmt"

	"composelens/internal/diag"
	"composelens/internal/exitcode"
	"composelens/internal/redact"
	"composelens/internal/version"
)

const (
	Schema      = "composelens.check.v0"
	Disclaimer  = "fixed ruleset over existing stage provenance — not a policy engine, not a provenance graph"
	RulesetName = "fixed-v0"
)

type Report struct {
	Schema      string          `json:"schema"`
	Product     string          `json:"product"`
	Version     string          `json:"version"`
	Disclaimer  string          `json:"disclaimer"`
	Ruleset     string          `json:"ruleset"`
	Findings    []FindingReport `json:"findings"`
	Counts      Counts          `json:"counts"`
	Evidence    string          `json:"evidence"`
	Certainty   string          `json:"certainty"`
	Policy      string          `json:"policy,omitempty"`
	Gate        string          `json:"gate,omitempty"`
	Code        string          `json:"code,omitempty"`
	Remediation string          `json:"remediation,omitempty"`
	Doc         string          `json:"doc,omitempty"`
}

type FindingReport struct {
	ID            string   `json:"id"`
	Name          string   `json:"name"`
	Severity      string   `json:"severity"`
	Target        string   `json:"target"`
	Kind          string   `json:"kind"`
	Message       string   `json:"message"`
	Provenance    []string `json:"provenance"`
	Secret        bool     `json:"secret"`
	Certainty     string   `json:"certainty"`
	Evidence      string   `json:"evidence"`
	Waived        bool     `json:"waived,omitempty"`
	WaiverExpires string   `json:"waiverExpires,omitempty"`
	// GraphNode names the provenance-graph node this finding refers to. It is
	// set in the report package only (report --json / --html).
	GraphNode *NodeRef `json:"graphNode,omitempty"`
}

// NodeRef identifies one provenance-graph node.
type NodeRef struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
}

type Counts struct {
	Error   int `json:"error"`
	Warning int `json:"warning"`
	Info    int `json:"info"`
	Waived  int `json:"waived"`
	Total   int `json:"total"`
}

func ruleName(id string) string {
	switch id {
	case CHK01:
		return "secret-inline"
	case CHK02:
		return "required-unset"
	case CHK03:
		return "profiled-dependency-gap"
	case CHK04:
		return "missing-target"
	case CHK05:
		return "env-shadowing"
	case CHK06:
		return "compose-rejects"
	default:
		return id
	}
}

func NewReport(r Result) Report {
	findings := make([]FindingReport, 0, len(r.Findings))
	var c Counts
	gate := r.Gate
	if gate == "" {
		gate = SevError
	}
	for _, f := range r.Findings {
		findings = append(findings, FindingReport{
			ID:            f.ID,
			Name:          ruleName(f.ID),
			Severity:      f.Severity,
			Target:        f.Target,
			Kind:          f.Kind,
			Message:       f.Message,
			Provenance:    append([]string{}, f.Provenance...),
			Secret:        f.Secret,
			Certainty:     f.Certainty,
			Evidence:      f.Evidence,
			Waived:        f.Waived,
			WaiverExpires: f.WaiverExpires,
		})
		if f.Waived {
			c.Waived++
			continue
		}
		switch f.Severity {
		case SevError:
			c.Error++
		case SevWarning:
			c.Warning++
		case SevInfo:
			c.Info++
		}
	}
	c.Total = len(findings)
	disclaimer := Disclaimer
	ruleset := RulesetName
	if r.PolicySchema != "" {
		disclaimer = PolicyDisclaimer
		ruleset = PolicyRuleset
	}
	rep := Report{
		Schema:     Schema,
		Product:    version.Name,
		Version:    version.Version,
		Disclaimer: disclaimer,
		Ruleset:    ruleset,
		Findings:   findings,
		Counts:     c,
		Evidence:   r.Evidence,
		Certainty:  r.Certainty,
		Policy:     r.PolicySchema,
		Gate:       gate,
	}
	if AssertionExit(r) == exitcode.Assertion {
		if ent, ok := diag.LookupID("exit.assertion"); ok {
			rep.Code = ent.ID
			rep.Remediation = ent.Remediation
			rep.Doc = ent.Doc
		}
	}
	return rep
}

func JSON(r Result) ([]byte, error) {
	return json.MarshalIndent(NewReport(r), "", "  ")
}

func Human(r Result) string {
	rep := NewReport(r)
	var b bytes.Buffer
	fmt.Fprintf(&b, "ComposeLens check — %s\n\n", rep.Disclaimer)
	fmt.Fprintf(&b, "ruleset: %s\n", rep.Ruleset)
	if rep.Policy != "" {
		fmt.Fprintf(&b, "policy: %s\n", redact.EscapeControls(rep.Policy))
	}
	fmt.Fprintf(&b, "findings: %d  errors: %d  warnings: %d  info: %d  waived: %d\n", rep.Counts.Total, rep.Counts.Error, rep.Counts.Warning, rep.Counts.Info, rep.Counts.Waived)
	fmt.Fprintf(&b, "gate: %s\n", rep.Gate)
	if rep.Counts.Total == 0 {
		fmt.Fprintf(&b, "  (none)\n")
		return b.String()
	}
	groups := []struct {
		label  string
		sev    string
		waived bool
	}{
		{"errors", SevError, false},
		{"warnings", SevWarning, false},
		{"info", SevInfo, false},
		{"waived", "", true},
	}
	for _, g := range groups {
		var rows []FindingReport
		for _, f := range rep.Findings {
			if g.waived {
				if f.Waived {
					rows = append(rows, f)
				}
				continue
			}
			if !f.Waived && f.Severity == g.sev {
				rows = append(rows, f)
			}
		}
		if len(rows) == 0 {
			continue
		}
		fmt.Fprintf(&b, "%s:\n", g.label)
		for _, f := range rows {
			fmt.Fprintf(&b, "  %s  %s  %s\n", f.ID, f.Severity, display(f.Target))
			fmt.Fprintf(&b, "    %s\n", display(f.Message))
			if f.Waived && f.WaiverExpires != "" {
				fmt.Fprintf(&b, "    waived until %s\n", f.WaiverExpires)
			}
			if len(f.Provenance) > 0 {
				fmt.Fprintf(&b, "    provenance: %s\n", joinProv(displayAll(f.Provenance)))
			}
		}
	}
	if rep.Code != "" {
		fmt.Fprintf(&b, "code: %s\nremediation: %s\nSee %s\n", rep.Code, rep.Remediation, rep.Doc)
	}
	return b.String()
}

func display(s string) string {
	return redact.DisplayHuman(s)
}

func displayAll(ss []string) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = display(s)
	}
	return out
}

func joinProv(ss []string) string {
	return joinComma(ss)
}

func joinComma(ss []string) string {
	if len(ss) == 0 {
		return ""
	}
	var b bytes.Buffer
	for i, s := range ss {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(s)
	}
	return b.String()
}
