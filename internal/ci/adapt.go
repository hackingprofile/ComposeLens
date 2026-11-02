// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"composelens/internal/check"
	"composelens/internal/redact"
)

const (
	defaultJSONName    = "composelens-check.json"
	defaultSARIFName   = "composelens-check.sarif"
	defaultSummaryName = "composelens-check.md"

	EnvJSONPath    = "COMPOSELENS_JSON_PATH"
	EnvSARIFPath   = "COMPOSELENS_SARIF_PATH"
	EnvSummaryPath = "COMPOSELENS_GITHUB_SUMMARY"
	EnvStepSummary = "GITHUB_STEP_SUMMARY"
	EnvFailOn      = "COMPOSELENS_FAIL_ON"
)

// ArtifactLinks are markdown references to emitted CI files (basenames).
type ArtifactLinks struct {
	JSON    string
	SARIF   string
	Summary string
}

// Annotation is one GitHub workflow command (error / warning / notice).
type Annotation struct {
	Level   string
	File    string
	Line    int
	Column  int
	Message string
}

// Bundle is every GitHub-annotation adapter derived from one check.Result.
type Bundle struct {
	Annotations []Annotation
	Log         []byte
	Summary     string
	JSON        []byte
	SARIF       []byte
}

// LinksFromEnv builds artifact link labels from wrapper-supplied paths.
func LinksFromEnv() ArtifactLinks {
	return ArtifactLinks{
		JSON:    linkName(os.Getenv(EnvJSONPath), defaultJSONName),
		SARIF:   linkName(os.Getenv(EnvSARIFPath), defaultSARIFName),
		Summary: linkName(os.Getenv(EnvSummaryPath), defaultSummaryName),
	}
}

func linkName(path, fallback string) string {
	path = strings.TrimSpace(path)
	if path == "" {
		return fallback
	}
	// Either separator: the variable may hold a Windows or a POSIX path.
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if base == "" || base == "." || base == ".." {
		return fallback
	}
	return base
}

// FromResult serializes JSON, SARIF, a Markdown step-summary (with artifact
// links), and GitHub workflow annotations from one check result. Locations
// match check.SARIF physicalLocation.
func FromResult(r check.Result, links ArtifactLinks) (Bundle, error) {
	js, err := check.JSON(r)
	if err != nil {
		return Bundle{}, err
	}
	sarif, err := check.SARIF(r)
	if err != nil {
		return Bundle{}, err
	}
	anns := annotations(r, strings.TrimSpace(os.Getenv(EnvWorkspace)))
	var log bytes.Buffer
	for i, a := range anns {
		if i > 0 {
			log.WriteByte('\n')
		}
		log.WriteString(FormatAnnotation(a))
	}
	if log.Len() > 0 {
		log.WriteByte('\n')
	}
	raw := log.Bytes()
	if raw == nil {
		raw = []byte{}
	}
	if links.JSON == "" {
		links.JSON = defaultJSONName
	}
	if links.SARIF == "" {
		links.SARIF = defaultSARIFName
	}
	if links.Summary == "" {
		links.Summary = defaultSummaryName
	}
	return Bundle{
		Annotations: anns,
		Log:         raw,
		Summary:     SummaryMarkdown(r, links, anns),
		JSON:        js,
		SARIF:       sarif,
	}, nil
}

func annotations(r check.Result, workspace string) []Annotation {
	out := make([]Annotation, 0, len(r.Findings))
	for _, f := range r.Findings {
		if f.Waived {
			continue
		}
		level := workflowLevel(f.Severity)
		if level == "" {
			continue
		}
		uri := annotationPath(r, f, workspace)
		if uri != "" && !portableAnnotationPath(uri) {
			uri = ""
		}
		line, col := 0, 0
		if uri != "" && f.Line > 0 {
			line = f.Line
			if f.Column > 0 {
				col = f.Column
			}
		}
		out = append(out, Annotation{
			Level:   level,
			File:    uri,
			Line:    line,
			Column:  col,
			Message: annotationMessage(f),
		})
	}
	return out
}

func workflowLevel(sev string) string {
	switch sev {
	case check.SevError:
		return "error"
	case check.SevWarning:
		return "warning"
	case check.SevInfo:
		return "notice"
	default:
		return ""
	}
}

func annotationMessage(f check.Finding) string {
	id := strings.TrimSpace(f.ID)
	msg := redact.DisplayHuman(f.Message)
	target := redact.DisplayHuman(f.Target)
	var b strings.Builder
	if id != "" {
		b.WriteString(id)
	}
	if target != "" {
		if b.Len() > 0 {
			b.WriteByte(' ')
		}
		b.WriteString(target)
	}
	if msg != "" {
		if b.Len() > 0 {
			b.WriteString(": ")
		}
		b.WriteString(msg)
	}
	s := b.String()
	if s == "" {
		s = "ComposeLens finding"
	}
	return s
}

func portableAnnotationPath(uri string) bool {
	uri = strings.TrimSpace(uri)
	if uri == "" {
		return false
	}
	if strings.Contains(uri, `\`) {
		return false
	}
	if filepath.IsAbs(filepath.FromSlash(uri)) {
		return false
	}
	if len(uri) >= 2 && uri[1] == ':' {
		return false
	}
	if strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, "//") {
		return false
	}
	lower := strings.ToLower(uri)
	if strings.HasPrefix(lower, "file:") {
		return false
	}
	if redact.LooksLikeSecret(uri) {
		return false
	}
	return true
}

// FormatAnnotation renders one GitHub workflow command.
// https://docs.github.com/en/actions/writing-workflows/choosing-what-your-workflow-does/workflow-commands-for-github-actions
func FormatAnnotation(a Annotation) string {
	var b strings.Builder
	b.WriteString("::")
	b.WriteString(a.Level)
	if a.File != "" && portableAnnotationPath(a.File) {
		b.WriteString(" file=")
		b.WriteString(escapeProperty(a.File))
		if a.Line > 0 {
			b.WriteString(",line=")
			b.WriteString(strconv.Itoa(a.Line))
			if a.Column > 0 {
				b.WriteString(",col=")
				b.WriteString(strconv.Itoa(a.Column))
			}
		}
	}
	b.WriteString("::")
	b.WriteString(escapeData(a.Message))
	return b.String()
}

func escapeData(s string) string {
	s = strings.ReplaceAll(s, "%", "%25")
	s = strings.ReplaceAll(s, "\r", "%0D")
	s = strings.ReplaceAll(s, "\n", "%0A")
	return s
}

func escapeProperty(s string) string {
	s = escapeData(s)
	s = strings.ReplaceAll(s, ":", "%3A")
	s = strings.ReplaceAll(s, ",", "%2C")
	return s
}

// SummaryMarkdown is a GITHUB_STEP_SUMMARY body: counts, findings, artifact links.
func SummaryMarkdown(r check.Result, links ArtifactLinks, anns []Annotation) string {
	rep := check.NewReport(r)
	var b strings.Builder
	b.WriteString("# ComposeLens check\n\n")
	fmt.Fprintf(&b, "findings: **%d** · errors: **%d** · warnings: **%d** · info: **%d** · waived: **%d**\n\n",
		rep.Counts.Total, rep.Counts.Error, rep.Counts.Warning, rep.Counts.Info, rep.Counts.Waived)
	fmt.Fprintf(&b, "gate: `%s` · ruleset: `%s`\n\n", rep.Gate, rep.Ruleset)
	if len(anns) == 0 && rep.Counts.Waived == 0 {
		b.WriteString("No unwaived findings.\n\n")
	} else {
		writeFindingSection(&b, "Errors", anns, "error")
		writeFindingSection(&b, "Warnings", anns, "warning")
		writeFindingSection(&b, "Notices", anns, "notice")
		var waived []check.FindingReport
		for _, f := range rep.Findings {
			if f.Waived {
				waived = append(waived, f)
			}
		}
		if len(waived) > 0 {
			b.WriteString("## Waived\n\n")
			for _, f := range waived {
				fmt.Fprintf(&b, "- %s %s — %s\n", mdCode(f.ID), mdCode(redact.DisplayHuman(f.Target)), mdCode(redact.DisplayHuman(f.Message)))
			}
			b.WriteString("\n")
		}
	}
	b.WriteString("## Artifacts\n\n")
	fmt.Fprintf(&b, "- JSON: %s\n", mdCode(links.JSON))
	fmt.Fprintf(&b, "- SARIF: %s\n", mdCode(links.SARIF))
	fmt.Fprintf(&b, "- Summary: %s\n", mdCode(links.Summary))
	b.WriteString("\n")
	b.WriteString("These files are local check adapters. ComposeLens does not upload SARIF or annotate a pull request by itself.\n")
	return b.String()
}

func writeFindingSection(b *strings.Builder, title string, anns []Annotation, level string) {
	var rows []Annotation
	for _, a := range anns {
		if a.Level == level {
			rows = append(rows, a)
		}
	}
	if len(rows) == 0 {
		return
	}
	fmt.Fprintf(b, "## %s\n\n", title)
	for _, a := range rows {
		loc := "_"
		if a.File != "" {
			loc = a.File
			if a.Line > 0 {
				loc = fmt.Sprintf("%s:%d", a.File, a.Line)
			}
		}
		fmt.Fprintf(b, "- %s — %s\n", mdCode(loc), mdCode(redact.DisplayHuman(a.Message)))
	}
	b.WriteString("\n")
}

// EnvWorkspace is the GitHub workspace that annotation paths are relative to.
const EnvWorkspace = "GITHUB_WORKSPACE"

// annotationPath is the annotation file= value for f: relative to the GitHub
// workspace when one is set, else the SARIF (project-relative) URI. A file
// outside the workspace gets no file (never a guessed basename).
func annotationPath(r check.Result, f check.Finding, workspace string) string {
	if workspace == "" {
		return check.PhysicalURI(r, f)
	}
	if strings.TrimSpace(f.File) == "" {
		return ""
	}
	rel, err := filepath.Rel(filepath.Clean(workspace), filepath.Clean(f.File))
	if err != nil {
		return ""
	}
	rel = filepath.ToSlash(rel)
	if rel == "." || rel == ".." || strings.HasPrefix(rel, "../") || filepath.IsAbs(rel) || redact.LooksLikeSecret(rel) {
		return ""
	}
	return rel
}

// mdCode renders s as a Markdown code span that s cannot close: the fence is
// one backtick longer than the longest backtick run inside s, and a space
// pads s when it starts or ends with a backtick (CommonMark code spans).
// Links, images and emphasis inside s stay literal text. Control characters
// are shown escaped so s stays on one line.
func mdCode(s string) string {
	s = redact.EscapeControls(s)
	longest, run := 0, 0
	for i := 0; i < len(s); i++ {
		if s[i] == '`' {
			run++
			if run > longest {
				longest = run
			}
			continue
		}
		run = 0
	}
	fence := strings.Repeat("`", longest+1)
	if strings.HasPrefix(s, "`") || strings.HasSuffix(s, "`") {
		s = " " + s + " "
	}
	return fence + s + fence
}
