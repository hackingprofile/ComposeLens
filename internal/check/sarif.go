// SPDX-License-Identifier: Apache-2.0

package check

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"composelens/internal/redact"
	"composelens/internal/version"
)

const (
	SARIFVersion = "2.1.0"
	SARIFSchema  = "https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json"
)

type sarifLog struct {
	Schema  string     `json:"$schema"`
	Version string     `json:"version"`
	Runs    []sarifRun `json:"runs"`
}

type sarifRun struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifDriver struct {
	Name           string      `json:"name"`
	Version        string      `json:"version,omitempty"`
	InformationURI string      `json:"informationUri,omitempty"`
	Rules          []sarifRule `json:"rules"`
}

type sarifRule struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription,omitempty"`
	DefaultConfiguration *sarifConfiguration `json:"defaultConfiguration,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifResult struct {
	RuleID       string             `json:"ruleId"`
	Level        string             `json:"level"`
	Message      sarifMessage       `json:"message"`
	Locations    []sarifLocation    `json:"locations,omitempty"`
	Suppressions []sarifSuppression `json:"suppressions,omitempty"`
}

type sarifLocation struct {
	PhysicalLocation *sarifPhysicalLocation `json:"physicalLocation,omitempty"`
	LogicalLocations []sarifLogicalLocation `json:"logicalLocations,omitempty"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           *sarifRegion          `json:"region,omitempty"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn,omitempty"`
}

type sarifLogicalLocation struct {
	FullyQualifiedName string `json:"fullyQualifiedName"`
	Kind               string `json:"kind,omitempty"`
}

type sarifSuppression struct {
	Kind          string `json:"kind"`
	Status        string `json:"status,omitempty"`
	Justification string `json:"justification,omitempty"`
}

func sarifLevel(sev string) string {
	switch sev {
	case SevError:
		return "error"
	case SevWarning:
		return "warning"
	case SevInfo:
		return "note"
	default:
		return "none"
	}
}

func SARIF(r Result) ([]byte, error) {
	rules := []sarifRule{
		{
			ID: CHK01, Name: ruleName(CHK01),
			ShortDescription:     sarifMessage{Text: "Secret-keyed or secret-looking value defined inline"},
			FullDescription:      sarifMessage{Text: "A secret-keyed or secret-looking value is defined inline in the effective Compose model. Use an external secret source. Values are never emitted."},
			DefaultConfiguration: &sarifConfiguration{Level: "warning"},
		},
		{
			ID: CHK02, Name: ruleName(CHK02),
			ShortDescription:     sarifMessage{Text: "Required interpolation is unset"},
			FullDescription:      sarifMessage{Text: "A ${VAR:?} / ${VAR?} required interpolation is in the required-error state. ComposeLens does not fabricate a value."},
			DefaultConfiguration: &sarifConfiguration{Level: "error"},
		},
		{
			ID: CHK03, Name: ruleName(CHK03),
			ShortDescription:     sarifMessage{Text: "Enabled service depends_on a profile-gated target"},
			FullDescription:      sarifMessage{Text: "An enabled service depends_on a target gated behind an inactive profile. Compose does not document auto-enabling that dependency."},
			DefaultConfiguration: &sarifConfiguration{Level: "warning"},
		},
		{
			ID: CHK04, Name: ruleName(CHK04),
			ShortDescription:     sarifMessage{Text: "include: or extends target is absent"},
			FullDescription:      sarifMessage{Text: "An include: or extends reference points at a missing file or service. Cycle and unsupported forms are not this check."},
			DefaultConfiguration: &sarifConfiguration{Level: "error"},
		},
		{
			ID: CHK05, Name: ruleName(CHK05),
			ShortDescription:     sarifMessage{Text: "Container-environment variable shadowed"},
			FullDescription:      sarifMessage{Text: "A container-environment variable is set by multiple sources and a lower-precedence source was overridden."},
			DefaultConfiguration: &sarifConfiguration{Level: "note"},
		},
		{
			ID: CHK06, Name: ruleName(CHK06),
			ShortDescription:     sarifMessage{Text: "Compose rejects this input"},
			FullDescription:      sarifMessage{Text: "docker compose config would refuse this file: an unknown top-level key, a non-string name or version, an invalid interpolation format, an include: that is not a list, or an include or extends cycle."},
			DefaultConfiguration: &sarifConfiguration{Level: "error"},
		},
	}
	results := make([]sarifResult, 0, len(r.Findings))
	base := r.sourceBase
	if base == "" {
		base = sourceBase(r.Findings)
	}
	for _, f := range r.Findings {
		loc := sarifLocation{
			LogicalLocations: []sarifLogicalLocation{{
				FullyQualifiedName: f.Target,
				Kind:               f.Kind,
			}},
		}
		if pl := physicalLocation(f, base); pl != nil {
			loc.PhysicalLocation = pl
		}
		res := sarifResult{
			RuleID:    f.ID,
			Level:     sarifLevel(f.Severity),
			Message:   sarifMessage{Text: f.Message},
			Locations: []sarifLocation{loc},
		}
		if f.Waived {
			just := "policy exception"
			if f.WaiverExpires != "" {
				just = "policy exception expires " + f.WaiverExpires
			}
			res.Suppressions = []sarifSuppression{{
				Kind:          "external",
				Status:        "accepted",
				Justification: just,
			}}
		}
		results = append(results, res)
	}
	log := sarifLog{
		Schema:  SARIFSchema,
		Version: SARIFVersion,
		Runs: []sarifRun{{
			Tool: sarifTool{Driver: sarifDriver{
				Name:    version.Name,
				Version: version.Version,
				Rules:   rules,
			}},
			Results: results,
		}},
	}
	return json.MarshalIndent(log, "", "  ")
}

func physicalLocation(f Finding, base string) *sarifPhysicalLocation {
	uri := portableURI(f.File, base)
	if uri == "" {
		return nil
	}
	pl := &sarifPhysicalLocation{
		ArtifactLocation: sarifArtifactLocation{URI: uri},
	}
	if f.Line > 0 {
		reg := &sarifRegion{StartLine: f.Line}
		if f.Column > 0 {
			reg.StartColumn = f.Column
		}
		pl.Region = reg
	}
	return pl
}

func sourceBase(findings []Finding) string {
	var files []string
	for _, f := range findings {
		if f.File != "" {
			files = append(files, f.File)
		}
	}
	return commonDir(files)
}

func commonDir(files []string) string {
	var dirs []string
	for _, f := range files {
		c := filepath.Clean(f)
		if c == "." || c == "" {
			continue
		}
		dirs = append(dirs, filepath.Dir(c))
	}
	if len(dirs) == 0 {
		return ""
	}
	prefix := dirs[0]
	for _, d := range dirs[1:] {
		for {
			rel, err := filepath.Rel(prefix, d)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				break
			}
			parent := filepath.Dir(prefix)
			if parent == prefix {
				return ""
			}
			prefix = parent
		}
	}
	return prefix
}

func portableURI(file, base string) string {
	file = strings.TrimSpace(file)
	if file == "" {
		return ""
	}
	file = filepath.Clean(file)
	uri := ""
	if base != "" {
		if rel, err := filepath.Rel(base, file); err == nil {
			rel = filepath.ToSlash(rel)
			if rel != "" && rel != "." && !strings.HasPrefix(rel, "../") && !filepath.IsAbs(rel) {
				uri = rel
			}
		}
	}
	if uri == "" || uri == "." || uriLooksAbsolute(uri) || redact.LooksLikeSecret(uri) {
		return ""
	}
	return uri
}

func uriLooksAbsolute(uri string) bool {
	if uri == "" {
		return false
	}
	if strings.Contains(uri, `\`) {
		return true
	}
	if strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		return true
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "file:") {
		return true
	}
	if len(uri) >= 2 && uri[1] == ':' {
		return true
	}
	return filepath.IsAbs(filepath.FromSlash(uri))
}

func validateSARIFURI(uri string) error {
	if strings.TrimSpace(uri) == "" {
		return fmt.Errorf("artifactLocation.uri is empty")
	}
	if uriLooksAbsolute(uri) {
		return fmt.Errorf("artifactLocation.uri must be project-relative, got %q", uri)
	}
	if redact.LooksLikeSecret(uri) {
		return fmt.Errorf("artifactLocation.uri must not contain a secret")
	}
	return nil
}

func ValidateSARIF(raw []byte) error {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return fmt.Errorf("sarif: not JSON: %w", err)
	}
	ver, _ := root["version"].(string)
	if ver != SARIFVersion {
		return fmt.Errorf("sarif: version must be %s, got %q", SARIFVersion, ver)
	}
	schema, _ := root["$schema"].(string)
	if schema != "" && !strings.Contains(strings.ToLower(schema), "sarif") {
		return fmt.Errorf("sarif: $schema does not name SARIF")
	}
	runs, ok := root["runs"].([]any)
	if !ok {
		return fmt.Errorf("sarif: runs is required")
	}
	if len(runs) == 0 {
		return fmt.Errorf("sarif: runs must contain at least one run")
	}
	for i, runv := range runs {
		run, ok := runv.(map[string]any)
		if !ok {
			return fmt.Errorf("sarif: runs[%d] must be an object", i)
		}
		tool, _ := run["tool"].(map[string]any)
		if tool == nil {
			return fmt.Errorf("sarif: runs[%d].tool is required", i)
		}
		driver, _ := tool["driver"].(map[string]any)
		if driver == nil {
			return fmt.Errorf("sarif: runs[%d].tool.driver is required", i)
		}
		name, _ := driver["name"].(string)
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("sarif: runs[%d].tool.driver.name is required", i)
		}
		ruleIDs := map[string]struct{}{}
		if rules, ok := driver["rules"].([]any); ok {
			for j, rv := range rules {
				rule, ok := rv.(map[string]any)
				if !ok {
					return fmt.Errorf("sarif: runs[%d].tool.driver.rules[%d] must be an object", i, j)
				}
				id, _ := rule["id"].(string)
				if strings.TrimSpace(id) == "" {
					return fmt.Errorf("sarif: runs[%d].tool.driver.rules[%d].id is required", i, j)
				}
				ruleIDs[id] = struct{}{}
			}
		}
		results, _ := run["results"].([]any)
		if results == nil {
			continue
		}
		for j, rv := range results {
			res, ok := rv.(map[string]any)
			if !ok {
				return fmt.Errorf("sarif: runs[%d].results[%d] must be an object", i, j)
			}
			msg, _ := res["message"].(map[string]any)
			if msg == nil {
				return fmt.Errorf("sarif: runs[%d].results[%d].message is required", i, j)
			}
			text, _ := msg["text"].(string)
			id, _ := msg["id"].(string)
			md, _ := msg["markdown"].(string)
			if strings.TrimSpace(text) == "" && strings.TrimSpace(id) == "" && strings.TrimSpace(md) == "" {
				return fmt.Errorf("sarif: runs[%d].results[%d].message needs text, id, or markdown", i, j)
			}
			if lvl, ok := res["level"].(string); ok && lvl != "" {
				switch lvl {
				case "none", "note", "warning", "error":
				default:
					return fmt.Errorf("sarif: runs[%d].results[%d].level %q is not a SARIF 2.1.0 level", i, j, lvl)
				}
			}
			ruleID, _ := res["ruleId"].(string)
			if ruleID != "" && len(ruleIDs) > 0 {
				if _, ok := ruleIDs[ruleID]; !ok {
					return fmt.Errorf("sarif: runs[%d].results[%d].ruleId %q is not in driver.rules", i, j, ruleID)
				}
			}
			if locs, ok := res["locations"].([]any); ok {
				for k, lv := range locs {
					loc, ok := lv.(map[string]any)
					if !ok {
						return fmt.Errorf("sarif: runs[%d].results[%d].locations[%d] must be an object", i, j, k)
					}
					pl, _ := loc["physicalLocation"].(map[string]any)
					if pl == nil {
						continue
					}
					art, _ := pl["artifactLocation"].(map[string]any)
					uri, _ := art["uri"].(string)
					if err := validateSARIFURI(uri); err != nil {
						return fmt.Errorf("sarif: runs[%d].results[%d].locations[%d].physicalLocation: %w", i, j, k, err)
					}
				}
			}
		}
	}
	return nil
}

// locationBase is the directory used to make SARIF URIs project-relative.
func (r Result) locationBase() string {
	if r.sourceBase != "" {
		return r.sourceBase
	}
	return sourceBase(r.Findings)
}

// PhysicalURI returns the SARIF artifactLocation.uri for f (project-relative,
// forward slashes), or "" when the finding has no portable physical location.
func PhysicalURI(r Result, f Finding) string {
	pl := physicalLocation(f, r.locationBase())
	if pl == nil {
		return ""
	}
	return pl.ArtifactLocation.URI
}

func FingerprintsFromJSON(raw []byte) ([]string, error) {
	var rep Report
	if err := json.Unmarshal(raw, &rep); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rep.Findings))
	for _, f := range rep.Findings {
		out = append(out, f.ID+"|"+f.Severity+"|"+f.Target)
	}
	return out, nil
}

func FingerprintsFromSARIF(raw []byte) ([]string, error) {
	var log sarifLog
	if err := json.Unmarshal(raw, &log); err != nil {
		return nil, err
	}
	var out []string
	for _, run := range log.Runs {
		for _, res := range run.Results {
			target := ""
			if len(res.Locations) > 0 && len(res.Locations[0].LogicalLocations) > 0 {
				target = res.Locations[0].LogicalLocations[0].FullyQualifiedName
			}
			sev := SevInfo
			switch res.Level {
			case "error":
				sev = SevError
			case "warning":
				sev = SevWarning
			case "note":
				sev = SevInfo
			}
			out = append(out, res.RuleID+"|"+sev+"|"+target)
		}
	}
	return out, nil
}

func FingerprintsFromHuman(text string) []string {
	var out []string
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "CHK") {
			continue
		}
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		out = append(out, parts[0]+"|"+parts[1]+"|"+parts[2])
	}
	return out
}

// WithLocationBase makes SARIF URIs relative to dir, the selected project
// directory. A finding whose file lies outside dir gets no physical location.
func (r Result) WithLocationBase(dir string) Result {
	r.sourceBase = filepath.Clean(dir)
	return r
}
