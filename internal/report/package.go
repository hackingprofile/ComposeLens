// SPDX-License-Identifier: Apache-2.0

// Package report assembles the self-contained JSON data package
// (composelens.report.v0). It does not recompute the model: callers pass
// existing inspect/graph/check/diff/differential results.
package report

import (
	"encoding/json"
	"sort"

	"composelens/internal/check"
	"composelens/internal/composeparse"
	"composelens/internal/diag"
	"composelens/internal/diff"
	"composelens/internal/differential"
	"composelens/internal/evidence"
	"composelens/internal/provgraph"
	"composelens/internal/version"
)

const (
	Schema      = "composelens.report.v0"
	Disclaimer  = "self-contained JSON report data package assembled from inspect, explain --all, check, diff, and differential — not an HTML viewer, not a new resolver"
	Determinism = "byte-stable-v0"
	GeneratedBy = "report --json"

	diffDisclaimer = "effective-config delta over the same Compose files — not a provenance graph, not an engine differential"
)

// Package is one offline-renderable JSON document. Nested graph/check/diff/
// differential objects keep their existing schema ids.
type Package struct {
	Schema       string              `json:"schema"`
	Product      string              `json:"product"`
	Version      string              `json:"version"`
	Disclaimer   string              `json:"disclaimer"`
	Determinism  string              `json:"determinism"`
	GeneratedBy  string              `json:"generatedBy"`
	Source       Source              `json:"source"`
	Graph        provgraph.Report    `json:"graph"`
	Check        CheckSection        `json:"check"`
	Diff         DiffSection         `json:"diff"`
	Differential differential.Report `json:"differential"`
	Diagnostics  []Diagnostic        `json:"diagnostics"`
	Evidence     string              `json:"evidence"`
	Certainty    string              `json:"certainty"`
}

type Source struct {
	ProjectDirectory string    `json:"projectDirectory"`
	Files            []File    `json:"files"`
	FileEvidence     string    `json:"fileEvidence"`
	Services         []Service `json:"services"`
	// ServiceSummary lists each unique service once, with every declaration
	// (file, line, column) across the selected files; Services keeps the
	// per-declaration list.
	ServiceSummary []ServiceSummary `json:"serviceSummary"`
}

// ServiceSummary is one unique service and where it is declared.
type ServiceSummary struct {
	Name         string                  `json:"name"`
	Identity     string                  `json:"identity"`
	Declarations []composeparse.Location `json:"declarations"`
}

type File struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Origin    string `json:"origin"`
	Index     int    `json:"index"`
	Evidence  string `json:"evidence"`
	Certainty string `json:"certainty"`
}

type Service struct {
	Name      string                `json:"name"`
	Identity  string                `json:"identity"`
	Location  composeparse.Location `json:"location"`
	Evidence  string                `json:"evidence"`
	Certainty string                `json:"certainty"`
}

type CheckSection struct {
	check.Report
	AssertionExit int `json:"assertionExit"`
}

type DiffSection struct {
	Schema      string `json:"schema"`
	Product     string `json:"product"`
	Version     string `json:"version"`
	Disclaimer  string `json:"disclaimer"`
	Empty       bool   `json:"empty"`
	ChangeCount int    `json:"changeCount"`
	Note        string `json:"note"`
	Evidence    string `json:"evidence"`
	Certainty   string `json:"certainty"`
}

type Diagnostic struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Remediation string `json:"remediation"`
	Doc         string `json:"doc"`
}

// Input is assembled from existing command builders. Nothing here is invented.
type Input struct {
	Project      string
	Files        []File
	Services     []Service
	Graph        provgraph.Graph
	Check        check.Result
	Diff         diff.Result
	DiffNote     string
	Differential differential.Report
	// FindingNodes is index-aligned with Check.Findings: the graph node each
	// finding refers to (nil when none resolves).
	FindingNodes []*check.NodeRef
}

func Assemble(in Input) Package {
	files := in.Files
	if files == nil {
		files = []File{}
	}
	services := in.Services
	if services == nil {
		services = []Service{}
	}
	fileEv := evidence.Known
	if len(files) == 0 {
		fileEv = evidence.Absent
	}
	checkRep := check.NewReport(in.Check)
	for i := range checkRep.Findings {
		if i < len(in.FindingNodes) {
			checkRep.Findings[i].GraphNode = in.FindingNodes[i]
		}
	}
	diags := diagnosticsFrom(checkRep)
	diffNote := in.DiffNote
	if diffNote == "" {
		diffNote = "same-selection assembly; report does not accept diff-only left/right flags"
	}
	return Package{
		Schema:      Schema,
		Product:     version.Name,
		Version:     version.Version,
		Disclaimer:  Disclaimer,
		Determinism: Determinism,
		GeneratedBy: GeneratedBy,
		Source: Source{
			ProjectDirectory: in.Project,
			Files:            files,
			FileEvidence:     fileEv,
			Services:         services,
			ServiceSummary:   summarizeServices(services),
		},
		Graph: provgraph.NewReport(in.Graph),
		Check: CheckSection{
			Report:        checkRep,
			AssertionExit: check.AssertionExit(in.Check),
		},
		Diff: DiffSection{
			Schema:      "composelens.diff.v0",
			Product:     version.Name,
			Version:     version.Version,
			Disclaimer:  diffDisclaimer,
			Empty:       len(in.Diff.Changes) == 0,
			ChangeCount: len(in.Diff.Changes),
			Note:        diffNote,
			Evidence:    in.Diff.Evidence,
			Certainty:   in.Diff.Certainty,
		},
		Differential: in.Differential,
		Diagnostics:  diags,
		Evidence:     evidence.Known,
		Certainty:    evidence.Proven,
	}
}

func diagnosticsFrom(rep check.Report) []Diagnostic {
	out := []Diagnostic{}
	if rep.Code == "" {
		return out
	}
	ent, ok := diag.LookupID(rep.Code)
	if !ok {
		return out
	}
	return []Diagnostic{{
		Code:        ent.ID,
		Message:     ent.Message,
		Remediation: ent.Remediation,
		Doc:         ent.Doc,
	}}
}

func Encode(p Package) ([]byte, error) {
	if p.Source.Files == nil {
		p.Source.Files = []File{}
	}
	if p.Source.Services == nil {
		p.Source.Services = []Service{}
	}
	if p.Diagnostics == nil {
		p.Diagnostics = []Diagnostic{}
	}
	if p.Graph.Nodes == nil {
		p.Graph.Nodes = []provgraph.NodeReport{}
	}
	if p.Check.Findings == nil {
		p.Check.Findings = []check.FindingReport{}
	}
	if p.Differential.Rows == nil {
		p.Differential.Rows = []differential.Row{}
	}
	raw, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

// summarizeServices groups service declarations by name, sorted by name;
// declarations keep their selection order.
func summarizeServices(services []Service) []ServiceSummary {
	index := map[string]int{}
	out := []ServiceSummary{}
	for _, s := range services {
		i, ok := index[s.Name]
		if !ok {
			i = len(out)
			index[s.Name] = i
			out = append(out, ServiceSummary{Name: s.Name, Identity: s.Identity, Declarations: []composeparse.Location{}})
		}
		out[i].Declarations = append(out[i].Declarations, s.Location)
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Name < out[b].Name })
	return out
}
