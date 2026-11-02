// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"composelens/internal/evidence"
)

const (
	Schema = "composelens.fixtax.v0"

	EnginePending   = "pending-engine"
	EngineMatched   = "matched"
	EngineDivergent = "divergent"
	EngineError     = "engine-error"

	KindBaseline    = "baseline"
	KindRegression  = "regression"
	KindPlatform    = "platform"
	KindAdversarial = "adversarial"
	KindSecurity    = "security"

	StatusPassed  = "passed"
	StatusFailed  = "failed"
	StatusSkipped = "skipped"
)

type Catalog struct {
	Schema   string    `yaml:"schema" json:"schema"`
	Fixtures []Fixture `yaml:"fixtures" json:"fixtures"`
}

type Fixture struct {
	ID          string     `yaml:"id" json:"id"`
	Feature     string     `yaml:"feature" json:"feature"`
	Kind        string     `yaml:"kind" json:"kind"`
	Description string     `yaml:"description" json:"description"`
	Provenance  Provenance `yaml:"provenance" json:"provenance"`
	Rationale   Rationale  `yaml:"rationale,omitempty" json:"rationale,omitempty"`
	Files       []string   `yaml:"files" json:"files"`
	EnvFiles    []string   `yaml:"envFiles,omitempty" json:"envFiles,omitempty"`
	Entry       string     `yaml:"entry,omitempty" json:"entry,omitempty"`
	Expected    Expected   `yaml:"expected" json:"expected"`
}

// Rationale is a verifiable public reference. Type is compose-spec, docs, or issue.
// Issue URLs must be real; this corpus cites compose-spec and official Docker docs only.
type Rationale struct {
	Type    string `yaml:"type" json:"type"`
	Ref     string `yaml:"ref" json:"ref"`
	Section string `yaml:"section,omitempty" json:"section,omitempty"`
}

type Provenance struct {
	Source string `yaml:"source" json:"source"`
	Note   string `yaml:"note,omitempty" json:"note,omitempty"`
}

type Expected struct {
	Engine       string       `yaml:"engine" json:"engine"`
	EnginePin    string       `yaml:"enginePin,omitempty" json:"enginePin,omitempty"`
	EngineFields []PathExpect `yaml:"engineFields,omitempty" json:"engineFields,omitempty"`
	Local        Local        `yaml:"local" json:"local"`
}

type Local struct {
	Assertion      string            `yaml:"assertion" json:"assertion"`
	Services       []string          `yaml:"services,omitempty" json:"services,omitempty"`
	Paths          []PathExpect      `yaml:"paths,omitempty" json:"paths,omitempty"`
	Env            map[string]string `yaml:"env,omitempty" json:"env,omitempty"`
	Profiles       []string          `yaml:"profiles,omitempty" json:"profiles,omitempty"`
	HostEnv        map[string]string `yaml:"hostEnv,omitempty" json:"hostEnv,omitempty"`
	CheckIDs       []string          `yaml:"checkIds,omitempty" json:"checkIds,omitempty"`
	Compare        string            `yaml:"compare,omitempty" json:"compare,omitempty"`
	Family         string            `yaml:"family,omitempty" json:"family,omitempty"`
	Service        string            `yaml:"service,omitempty" json:"service,omitempty"`
	Key            string            `yaml:"key,omitempty" json:"key,omitempty"`
	Value          string            `yaml:"value,omitempty" json:"value,omitempty"`
	State          string            `yaml:"state,omitempty" json:"state,omitempty"`
	Form           string            `yaml:"form,omitempty" json:"form,omitempty"`
	HasCycle       *bool             `yaml:"hasCycle,omitempty" json:"hasCycle,omitempty"`
	Certainty      string            `yaml:"certainty,omitempty" json:"certainty,omitempty"`
	GOOS           string            `yaml:"goos,omitempty" json:"goos,omitempty"`
	Project        string            `yaml:"project,omitempty" json:"project,omitempty"`
	MinUnsupported int               `yaml:"minUnsupported,omitempty" json:"minUnsupported,omitempty"`
}

type PathExpect struct {
	Path       string `yaml:"path" json:"path"`
	Value      string `yaml:"value,omitempty" json:"value,omitempty"`
	State      string `yaml:"state,omitempty" json:"state,omitempty"`
	Action     string `yaml:"action,omitempty" json:"action,omitempty"`
	Resolved   string `yaml:"resolved,omitempty" json:"resolved,omitempty"`
	Certainty  string `yaml:"certainty,omitempty" json:"certainty,omitempty"`
	AbsentPath bool   `yaml:"absentPath,omitempty" json:"absentPath,omitempty"`
	// PosixValue is the engine value on Linux and macOS when it differs from
	// Value (see EngineValues).
	PosixValue string `yaml:"posixValue,omitempty" json:"posixValue,omitempty"`
}

type Report struct {
	Schema        string            `json:"schema"`
	Disclaimer    string            `json:"disclaimer"`
	Total         int               `json:"total"`
	Passed        int               `json:"passed"`
	Failed        int               `json:"failed"`
	Skipped       int               `json:"skipped"`
	PendingEngine int               `json:"pendingEngine"`
	Undeclared    []string          `json:"undeclared"`
	ByFeature     map[string]Counts `json:"byFeature"`
	ByKind        map[string]Counts `json:"byKind"`
	Results       []Result          `json:"results"`
	Evidence      string            `json:"evidence"`
	Certainty     string            `json:"certainty"`
}

type Counts struct {
	Total         int `json:"total"`
	Passed        int `json:"passed"`
	Failed        int `json:"failed"`
	Skipped       int `json:"skipped"`
	PendingEngine int `json:"pendingEngine"`
}

type Result struct {
	ID            string `json:"id"`
	Feature       string `json:"feature"`
	Kind          string `json:"kind"`
	Status        string `json:"status"`
	PendingEngine bool   `json:"pendingEngine"`
	Detail        string `json:"detail,omitempty"`
}

func emptyReport() Report {
	return Report{
		Schema:     Schema,
		Disclaimer: "local fixture harness — pending-engine until live-pinned; matched/divergent/engine-error rows are catalogued against docker compose config",
		ByFeature:  map[string]Counts{},
		ByKind:     map[string]Counts{},
		Results:    []Result{},
		Undeclared: []string{},
		Evidence:   evidence.Known,
		Certainty:  evidence.Proven,
	}
}
