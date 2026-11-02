// SPDX-License-Identifier: Apache-2.0

package differential

import "composelens/internal/evidence"

const (
	Schema = "composelens.differential.v0"

	StateMatch        = "match"
	StateDivergent    = "divergent"
	StateOnlyInternal = "only-internal"
	StateOnlyEngine   = "only-engine"
	StateUncertain    = "uncertain"

	KindService = "service"
	KindField   = "field"
	KindEnv     = "env"
)

// Report is a minimal internal-vs-engine comparison. Divergences are findings,
// not product failures. Values are redacted before emission.
type Report struct {
	Schema      string `json:"schema"`
	Disclaimer  string `json:"disclaimer"`
	EngineState string `json:"engineState"`
	SkipReason  string `json:"engineSkipReason,omitempty"`
	Version     string `json:"engineVersion,omitempty"`
	Command     string `json:"engineCommand,omitempty"`
	Project     string `json:"projectDirectory,omitempty"`
	Rows        []Row  `json:"rows"`
	Summary     Counts `json:"summary"`
	Evidence    string `json:"evidence"`
	Certainty   string `json:"certainty"`
}

type Row struct {
	Path           string `json:"path"`
	Kind           string `json:"kind"`
	State          string `json:"state"`
	Internal       string `json:"internal,omitempty"`
	Engine         string `json:"engine,omitempty"`
	Secret         bool   `json:"secret"`
	Certainty      string `json:"certainty"`
	Evidence       string `json:"evidence"`
	Detail         string `json:"detail,omitempty"`
	Classification string `json:"classification,omitempty"` // by-design | known-limitation
}

type Counts struct {
	Match        int `json:"match"`
	Divergent    int `json:"divergent"`
	OnlyInternal int `json:"onlyInternal"`
	OnlyEngine   int `json:"onlyEngine"`
	Uncertain    int `json:"uncertain"`
}

type Meta struct {
	EngineState string
	// SkipReason explains a skipped capture (engine state "skipped").
	SkipReason string
	Version    string
	Command    string
	Project    string
}

func emptyReport(meta Meta) Report {
	return Report{
		Schema:      Schema,
		Disclaimer:  "internal model vs live docker compose config — divergences are findings, not a claim of engine parity; not a stage fix",
		EngineState: meta.EngineState,
		SkipReason:  meta.SkipReason,
		Version:     meta.Version,
		Command:     meta.Command,
		Project:     meta.Project,
		Rows:        []Row{},
		Evidence:    evidence.Known,
		Certainty:   evidence.Proven,
	}
}

func (r *Report) add(row Row) {
	if row.Certainty == "" {
		row.Certainty = evidence.Proven
	}
	if row.Evidence == "" {
		row.Evidence = evidence.Known
	}
	if row.Secret {
		if row.Internal != "" {
			row.Internal = "[redacted]"
		}
		if row.Engine != "" {
			row.Engine = "[redacted]"
		}
	}
	r.Rows = append(r.Rows, row)
	switch row.State {
	case StateMatch:
		r.Summary.Match++
	case StateDivergent:
		r.Summary.Divergent++
	case StateOnlyInternal:
		r.Summary.OnlyInternal++
	case StateOnlyEngine:
		r.Summary.OnlyEngine++
	case StateUncertain:
		r.Summary.Uncertain++
	}
}
