// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/differential"
	"composelens/internal/discover"
	"composelens/internal/engineadapter"
	"composelens/internal/envsrc"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
)

const CorpusEnginePin = "v5.4.0"

type CorpusRow struct {
	ID           string
	Feature      string
	EngineExpect string
	Pin          string
	LiveVersion  string
	LiveState    string
	InScope      []differential.Row
	Project      string
	Err          string
}

func EngineAnchored(fx Fixture) bool {
	switch fx.Expected.Engine {
	case EngineMatched, EngineDivergent, EngineError:
		return true
	default:
		return false
	}
}

func InScopeRow(row differential.Row) bool {
	switch row.Kind {
	case differential.KindEnv:
		return true
	case differential.KindField:
		rest := row.Path
		if i := strings.LastIndex(rest, "."); i >= 0 {
			rest = rest[i+1:]
		}
		switch rest {
		case "image", "hostname", "working_dir", "user", "ports", "command", "entrypoint", "dns", "volumes":
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func RunCorpusFixture(ctx context.Context, fixturesRoot string, fx Fixture, environ []string) CorpusRow {
	out := CorpusRow{ID: fx.ID, Feature: fx.Feature, EngineExpect: fx.Expected.Engine, Pin: fx.Expected.EnginePin}
	project, composeFiles, err := corpusProject(fixturesRoot, fx)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	out.Project = project
	in, err := corpusInternal(project, composeFiles, absEnvFiles(fixturesRoot, fx.EnvFiles), environ)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	cap := engineadapter.DefaultRunner().Capture(ctx, engineadapter.Request{
		ProjectDir: project,
		Files:      composeFiles,
		EnvFiles:   absEnvFiles(fixturesRoot, fx.EnvFiles),
	})
	out.LiveVersion = cap.Version
	out.LiveState = cap.State
	if fx.Expected.Engine == EngineError {
		if cap.State != engineadapter.StateEngineError {
			out.Err = fmt.Sprintf("want engine-error, got %s: %s", cap.State, cap.Detail)
			return out
		}
		return out
	}
	if cap.State != engineadapter.StateCaptured {
		out.Err = fmt.Sprintf("engine state=%s detail=%s", cap.State, cap.Detail)
		return out
	}
	eng, err := differential.ParseConfig(cap.ConfigStdout)
	if err != nil {
		out.Err = err.Error()
		return out
	}
	rep := differential.CompareInputs(in, eng, differential.Meta{
		EngineState: cap.State,
		Version:     cap.Version,
		Command:     cap.ConfigCommand,
		Project:     project,
	})
	for _, row := range rep.Rows {
		if InScopeRow(row) {
			out.InScope = append(out.InScope, row)
		}
	}
	if err := checkCorpusExpect(fx, out); err != nil {
		out.Err = err.Error()
	}
	return out
}

func checkCorpusExpect(fx Fixture, row CorpusRow) error {
	switch fx.Expected.Engine {
	case EngineMatched:
		for _, r := range row.InScope {
			if r.State != differential.StateMatch {
				return fmt.Errorf("%s %s want match, got %s internal=%q engine=%q", r.Kind, r.Path, r.State, r.Internal, r.Engine)
			}
		}
		if len(row.InScope) == 0 {
			return fmt.Errorf("no in-scope rows")
		}
		return matchEngineFields(fx, row)
	case EngineDivergent:
		saw := false
		for _, r := range row.InScope {
			if r.State == differential.StateDivergent || r.State == differential.StateOnlyEngine || r.State == differential.StateOnlyInternal {
				saw = true
				break
			}
		}
		if !saw {
			return fmt.Errorf("catalogued as divergent but in-scope rows all matched")
		}
		return matchEngineFields(fx, row)
	default:
		return nil
	}
}

func matchEngineFields(fx Fixture, row CorpusRow) error {
	by := map[string]differential.Row{}
	for _, r := range row.InScope {
		by[r.Path] = r
	}
	for _, pe := range fx.Expected.EngineFields {
		got, ok := by[pe.Path]
		if !ok {
			return fmt.Errorf("missing live in-scope path %s", pe.Path)
		}
		wants := EngineValues(pe, row.Project, runtime.GOOS)
		if !slices.Contains(wants, got.Engine) {
			return fmt.Errorf("%s engine %q want %q (catalog is live-pinned, not ComposeLens)", pe.Path, got.Engine, strings.Join(wants, `" or "`))
		}
	}
	return nil
}

// EngineValues resolves a catalog engine value for a project directory on
// one operating system and returns every form the engine may print:
//
//   - posixValue replaces value on Linux and macOS when the engine reads
//     the file differently there (a backslash is a file-name character on
//     those systems, so ".\rel" stays a literal name);
//   - "{project}" is the project directory and "{sep}" its path separator on
//     that system; a backslash is never rewritten;
//   - "{optional: TEXT}" is text that some Compose releases print and others
//     leave out, such as the create_host_path=true a short bind implies.
func EngineValues(pe PathExpect, project, goos string) []string {
	v := pe.Value
	if goos != "windows" && pe.PosixValue != "" {
		v = pe.PosixValue
	}
	sep := "/"
	if goos == "windows" {
		sep = `\`
	}
	v = strings.ReplaceAll(v, "{sep}", sep)
	v = strings.ReplaceAll(v, "{project}", project)
	out := []string{v}
	for {
		var next []string
		changed := false
		for _, s := range out {
			i := strings.Index(s, "{optional:")
			if i < 0 {
				next = append(next, s)
				continue
			}
			j := strings.Index(s[i:], "}")
			if j < 0 {
				next = append(next, s)
				continue
			}
			changed = true
			text := s[i+len("{optional:") : i+j]
			rest := s[i+j+1:]
			next = append(next, s[:i]+rest, s[:i]+text+rest)
		}
		out = next
		if !changed {
			return out
		}
	}
}

// EngineNote describes the engine a live row ran against next to the version
// the catalog values were recorded with. Any installed Compose is accepted:
// rows are compared value by value, and the note is logged as evidence.
func EngineNote(recorded, live string) string {
	switch {
	case live == "":
		return "engine version unknown; catalog recorded against " + recorded
	case recorded == "" || live == recorded || strings.Contains(live, recorded):
		return "engine " + live
	default:
		return "engine " + live + " (catalog recorded against " + recorded + ")"
	}
}

func corpusProject(root string, fx Fixture) (project string, compose []string, err error) {
	entry := fx.Entry
	if entry == "" {
		for _, f := range fx.Files {
			low := strings.ToLower(f)
			if strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".json") {
				entry = f
				break
			}
		}
	}
	if entry == "" {
		return "", nil, fmt.Errorf("%s: no compose file", fx.ID)
	}
	abs, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(entry)))
	if err != nil {
		return "", nil, err
	}
	project = filepath.Dir(abs)
	for _, f := range fx.Files {
		low := strings.ToLower(f)
		if strings.HasSuffix(low, ".yaml") || strings.HasSuffix(low, ".yml") || strings.HasSuffix(low, ".json") {
			p, err := filepath.Abs(filepath.Join(root, filepath.FromSlash(f)))
			if err != nil {
				return "", nil, err
			}
			compose = append(compose, p)
		}
	}
	return project, compose, nil
}

func absEnvFiles(root string, rels []string) []string {
	var out []string
	for _, r := range rels {
		out = append(out, filepath.Join(root, filepath.FromSlash(r)))
	}
	return out
}

func corpusInternal(project string, files, envFiles, environ []string) (explain.Input, error) {
	fp, err := redact.NewFingerprinter()
	if err != nil {
		return explain.Input{}, err
	}
	table, err := interp.Load(project, envFiles, project, environ, fp)
	if err != nil {
		return explain.Input{}, err
	}
	var overlay []*composeparse.Document
	var getter interp.Getter
	if table != nil {
		getter = table
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return explain.Input{}, err
		}
		doc, err := composeparse.Parse(discover.File{Path: path, Bytes: raw, Origin: "corpus"})
		if err != nil {
			return explain.Input{}, err
		}
		expanded := include.Expand(doc, include.DiskLoad, getter)
		overlay = append(overlay, expanded.Docs...)
	}
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.DiskLoad, getter)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(nil, environ)
	activated := profiles.Activate(merged, active)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(environ), getter)
	if err != nil {
		return explain.Input{}, err
	}
	return explain.Input{Merge: merged, Profiles: activated, Container: cen}, nil
}
