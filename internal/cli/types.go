// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"composelens/internal/composeparse"
	"composelens/internal/engine"
	"composelens/internal/enginecap"
	"composelens/internal/interp"
	"composelens/internal/version"
)

type explainReport struct {
	Schema     string               `json:"schema"`
	Product    string               `json:"product"`
	Version    string               `json:"version"`
	Disclaimer string               `json:"disclaimer"`
	Target     explainTargetReport  `json:"target"`
	State      string               `json:"state"`
	Reason     string               `json:"reason,omitempty"`
	Stages     []explainStageReport `json:"stages"`
	Effective  ValueView            `json:"effective"`
	Secret     bool                 `json:"secret"`
	FinalStage string               `json:"finalStage,omitempty"`
	Certainty  string               `json:"certainty"`
	Evidence   string               `json:"evidence"`
}

type explainTargetReport struct {
	Raw     string `json:"raw"`
	Kind    string `json:"kind"`
	Service string `json:"service,omitempty"`
	Path    string `json:"path,omitempty"`
	Key     string `json:"key,omitempty"`
}

type explainStageReport struct {
	Name       string    `json:"name"`
	Summary    string    `json:"summary"`
	Path       string    `json:"path,omitempty"`
	Value      ValueView `json:"value"`
	Raw        ValueView `json:"raw"`
	State      string    `json:"state,omitempty"`
	Source     string    `json:"source,omitempty"`
	Winner     string    `json:"winner,omitempty"`
	Origin     string    `json:"origin,omitempty"`
	Chain      []string  `json:"chain,omitempty"`
	Overridden []string  `json:"overridden,omitempty"`
	Secret     bool      `json:"secret"`
	Certainty  string    `json:"certainty,omitempty"`
	Evidence   string    `json:"evidence,omitempty"`
	Reason     string    `json:"reason,omitempty"`
	// Line and Column locate the winning source of this stage (omitted when
	// unknown).
	Line   int `json:"line,omitempty"`
	Column int `json:"column,omitempty"`
}

type versionReport struct {
	Schema  string `json:"schema"`
	Name    string `json:"name"`
	Version string `json:"version"`
}

func newVersionReport() versionReport {
	return versionReport{
		Schema:  "composelens.version.v0",
		Name:    version.Name,
		Version: version.Version,
	}
}

type unsupportedReport struct {
	Schema  string `json:"schema"`
	Command string `json:"command"`
	State   string `json:"state"`
	Message string `json:"message"`
}

type errorReport struct {
	Schema      string `json:"schema"`
	State       string `json:"state"`
	Message     string `json:"message"`
	Code        string `json:"code,omitempty"`
	Remediation string `json:"remediation,omitempty"`
	Doc         string `json:"doc,omitempty"`
}

type PlatformInfo struct {
	OS        string `json:"os"`
	Arch      string `json:"arch"`
	Compiler  string `json:"compiler"`
	NumCPU    int    `json:"numCPU"`
	Shell     string `json:"shell,omitempty"`
	Certainty string `json:"certainty"`
}

type FileReport struct {
	Path      string `json:"path"`
	Digest    string `json:"digest"`
	Origin    string `json:"origin"`
	Index     int    `json:"index"`
	Evidence  string `json:"evidence"`
	Certainty string `json:"certainty"`
}

type InputsInfo struct {
	ProjectDirectory string       `json:"projectDirectory"`
	Files            []FileReport `json:"files"`
	FileEvidence     string       `json:"fileEvidence"`
}

type FeatureInfo struct {
	Implemented []string `json:"implemented"`
	Deferred    []string `json:"deferred"`
}

type reproduceReport struct {
	Schema           string   `json:"schema"`
	Product          string   `json:"product"`
	Version          string   `json:"version"`
	Disclaimer       string   `json:"disclaimer"`
	Argv             []string `json:"argv"`
	Command          string   `json:"command"`
	ProjectDirectory string   `json:"projectDirectory"`
	Files            []string `json:"files"`
	EnvFiles         []string `json:"envFiles,omitempty"`
	Profiles         []string `json:"profiles,omitempty"`
	Evidence         string   `json:"evidence"`
	Certainty        string   `json:"certainty"`
}

type doctorReport struct {
	Schema             string           `json:"schema"`
	Product            string           `json:"product"`
	Version            string           `json:"version"`
	Platform           PlatformInfo     `json:"platform"`
	Engine             engine.Info      `json:"engine"`
	EngineCapabilities enginecap.Report `json:"engineCapabilities"`
	Inputs             InputsInfo       `json:"inputs"`
	Features           FeatureInfo      `json:"features"`
	Evidence           string           `json:"evidence"`
}

type ServiceReport struct {
	Name      string                `json:"name"`
	Location  composeparse.Location `json:"location"`
	Evidence  string                `json:"evidence"`
	Certainty string                `json:"certainty"`
}

type ValueView struct {
	State    string  `json:"state"`
	Redacted bool    `json:"redacted"`
	Text     *string `json:"text"`
}

type EnvSourceReport struct {
	Reason      string    `json:"reason,omitempty"`
	Stage       string    `json:"stage"`
	Path        *string   `json:"path"`
	Line        *int      `json:"line"`
	Fingerprint string    `json:"fingerprint"`
	Value       ValueView `json:"value"`
	Certainty   string    `json:"certainty"`
}

type EnvKeyReport struct {
	Key      string            `json:"key"`
	Secret   bool              `json:"secret"`
	Evidence string            `json:"evidence"`
	Sources  []EnvSourceReport `json:"sources"`
}

type UnappliedEnvSource struct {
	Stage     string `json:"stage"`
	Path      string `json:"path"`
	Applied   bool   `json:"applied"`
	Certainty string `json:"certainty"`
	Evidence  string `json:"evidence"`
}

type inspectReport struct {
	Schema                         string                       `json:"schema"`
	Product                        string                       `json:"product"`
	Version                        string                       `json:"version"`
	View                           string                       `json:"view"`
	Disclaimer                     string                       `json:"disclaimer"`
	ProjectDirectory               string                       `json:"projectDirectory"`
	Files                          []FileReport                 `json:"files"`
	FileEvidence                   string                       `json:"fileEvidence"`
	Services                       []ServiceReport              `json:"services"`
	Environment                    []EnvKeyReport               `json:"environment"`
	UnappliedSources               []UnappliedEnvSource         `json:"unappliedSources,omitempty"`
	InterpolationDisclaimer        string                       `json:"interpolationDisclaimer"`
	Interpolation                  []InterpValueReport          `json:"interpolation"`
	IncludesDisclaimer             string                       `json:"includesDisclaimer"`
	Includes                       []IncludeGraphReport         `json:"includes"`
	ExtendsDisclaimer              string                       `json:"extendsDisclaimer"`
	Extends                        []ExtendsGraphReport         `json:"extends"`
	MergeDisclaimer                string                       `json:"mergeDisclaimer"`
	Merge                          []MergeFieldReport           `json:"merge"`
	ProfilesDisclaimer             string                       `json:"profilesDisclaimer"`
	ActiveProfiles                 []ActiveProfileReport        `json:"activeProfiles"`
	ProfileServices                []ProfileServiceReport       `json:"profileServices"`
	ContainerEnvironmentDisclaimer string                       `json:"containerEnvironmentDisclaimer"`
	ContainerEnvironment           []ContainerEnvServiceReport  `json:"containerEnvironment"`
	NormalizationDisclaimer        string                       `json:"normalizationDisclaimer"`
	Normalization                  []NormalizationServiceReport `json:"normalization"`
	Evidence                       string                       `json:"evidence"`
}

type IncludeGraphReport struct {
	File     string             `json:"file"`
	HasCycle bool               `json:"hasCycle"`
	Refs     []IncludeRefReport `json:"refs"`
}

type IncludeRefReport struct {
	Form              string              `json:"form"`
	Path              string              `json:"path"`
	Resolved          string              `json:"resolved,omitempty"`
	State             string              `json:"state"`
	Reason            string              `json:"reason,omitempty"`
	Certainty         string              `json:"certainty"`
	Evidence          string              `json:"evidence"`
	UnsupportedFields []string            `json:"unsupportedFields,omitempty"`
	CycleVia          []string            `json:"cycleVia,omitempty"`
	Nested            *IncludeGraphReport `json:"nested,omitempty"`
}

type ExtendsGraphReport struct {
	File     string             `json:"file"`
	HasCycle bool               `json:"hasCycle"`
	Refs     []ExtendsRefReport `json:"refs"`
}

type ExtendsRefReport struct {
	Name        string            `json:"name"`
	Form        string            `json:"form,omitempty"`
	Service     string            `json:"service,omitempty"`
	File        string            `json:"file,omitempty"`
	Resolved    string            `json:"resolved,omitempty"`
	State       string            `json:"state"`
	Reason      string            `json:"reason,omitempty"`
	Certainty   string            `json:"certainty"`
	Evidence    string            `json:"evidence"`
	Excluded    []string          `json:"excluded,omitempty"`
	CycleVia    []string          `json:"cycleVia,omitempty"`
	BaseFile    string            `json:"baseFile,omitempty"`
	BaseService string            `json:"baseService,omitempty"`
	Nested      *ExtendsRefReport `json:"nested,omitempty"`
}

type InterpValueReport struct {
	Path        string                `json:"path"`
	Location    composeparse.Location `json:"location"`
	Raw         string                `json:"raw"`
	Form        string                `json:"form"`
	State       string                `json:"state"`
	Source      *interpSourceReport   `json:"source"`
	Variables   []interp.Variable     `json:"variables"`
	Value       ValueView             `json:"value"`
	Error       *string               `json:"error"`
	Fingerprint string                `json:"fingerprint,omitempty"`
	Certainty   string                `json:"certainty"`
	Evidence    string                `json:"evidence"`
}

type interpSourceReport struct {
	Key   string  `json:"key"`
	Stage string  `json:"stage,omitempty"`
	Path  *string `json:"path"`
	Line  *int    `json:"line"`
}

type MergeFieldReport struct {
	Path               string             `json:"path"`
	Action             string             `json:"action"`
	Winner             string             `json:"winner"`
	Line               int                `json:"line,omitempty"`
	Value              ValueView          `json:"value"`
	Overridden         []MergeContributor `json:"overridden"`
	IncludeChain       []string           `json:"includeChain,omitempty"`
	ExtendsOrigin      string             `json:"extendsOrigin,omitempty"`
	ExtendsChain       []string           `json:"extendsChain,omitempty"`
	ExtendsBaseFile    string             `json:"extendsBaseFile,omitempty"`
	ExtendsBaseService string             `json:"extendsBaseService,omitempty"`
	Certainty          string             `json:"certainty"`
	Evidence           string             `json:"evidence"`
}

type MergeContributor struct {
	File   string    `json:"file"`
	Line   int       `json:"line,omitempty"`
	Action string    `json:"action,omitempty"`
	Value  ValueView `json:"value"`
}

type ActiveProfileReport struct {
	Name      string `json:"name"`
	Source    string `json:"source"`
	Redacted  bool   `json:"redacted"`
	Evidence  string `json:"evidence"`
	Certainty string `json:"certainty"`
}

type ProfileServiceReport struct {
	Name          string   `json:"name"`
	State         string   `json:"state"`
	Reason        string   `json:"reason"`
	Listed        []string `json:"listed"`
	Matched       *string  `json:"matched"`
	MatchedSource *string  `json:"matchedSource"`
	ImplicitOf    *string  `json:"implicitOf"`
	Certainty     string   `json:"certainty"`
	Evidence      string   `json:"evidence"`
}

type ContainerEnvServiceReport struct {
	Service   string                   `json:"service"`
	Files     []ContainerEnvFileReport `json:"files"`
	Variables []ContainerEnvVarReport  `json:"variables"`
}

type ContainerEnvFileReport struct {
	Path      string `json:"path"`
	Resolved  string `json:"resolved,omitempty"`
	State     string `json:"state"`
	Required  bool   `json:"required"`
	Format    string `json:"format,omitempty"`
	Reason    string `json:"reason,omitempty"`
	Certainty string `json:"certainty"`
	Evidence  string `json:"evidence"`
}

type ContainerEnvVarReport struct {
	Key        string                     `json:"key"`
	State      string                     `json:"state"`
	Winner     ContainerEnvSourceReport   `json:"winner"`
	Value      ValueView                  `json:"value"`
	Overridden []ContainerEnvSourceReport `json:"overridden"`
	Reason     string                     `json:"reason,omitempty"`
	Certainty  string                     `json:"certainty"`
	Evidence   string                     `json:"evidence"`
}

type ContainerEnvSourceReport struct {
	Kind  string    `json:"kind"`
	Path  string    `json:"path,omitempty"`
	Line  int       `json:"line,omitempty"`
	Form  string    `json:"form,omitempty"`
	Value ValueView `json:"value"`
}

type NormalizationServiceReport struct {
	Service     string                    `json:"service"`
	Ports       []NormalizationItemReport `json:"ports"`
	Volumes     []NormalizationItemReport `json:"volumes"`
	Labels      []NormalizationItemReport `json:"labels"`
	Command     *NormalizationItemReport  `json:"command,omitempty"`
	Entrypoint  *NormalizationItemReport  `json:"entrypoint,omitempty"`
	Healthcheck *NormalizationItemReport  `json:"healthcheck,omitempty"`
}

type NormalizationItemReport struct {
	Key       string    `json:"key,omitempty"`
	Form      string    `json:"form,omitempty"`
	Kind      string    `json:"kind,omitempty"`
	Canonical string    `json:"canonical,omitempty"`
	Source    string    `json:"source"`
	Line      int       `json:"line,omitempty"`
	Value     ValueView `json:"value"`
	Certainty string    `json:"certainty"`
	Evidence  string    `json:"evidence"`
	Reason    string    `json:"reason,omitempty"`
}

type diffReport struct {
	Schema     string              `json:"schema"`
	Product    string              `json:"product"`
	Version    string              `json:"version"`
	Disclaimer string              `json:"disclaimer"`
	Left       diffSelectionReport `json:"left"`
	Right      diffSelectionReport `json:"right"`
	Changes    []diffChangeReport  `json:"changes"`
	Empty      bool                `json:"empty"`
	Evidence   string              `json:"evidence"`
	Certainty  string              `json:"certainty"`
}

type diffSelectionReport struct {
	Profiles []string `json:"profiles"`
	EnvFiles []string `json:"envFiles"`
}

type diffChangeReport struct {
	Target string         `json:"target"`
	Kind   string         `json:"kind"`
	Change string         `json:"change"`
	Left   diffSideReport `json:"left"`
	Right  diffSideReport `json:"right"`
	Secret bool           `json:"secret"`
}

type diffSideReport struct {
	Present bool      `json:"present"`
	Value   ValueView `json:"value"`
	Source  string    `json:"source,omitempty"`
	State   string    `json:"state,omitempty"`
}
