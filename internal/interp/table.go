// SPDX-License-Identifier: Apache-2.0

package interp

import (
	"fmt"
	"os"
	"path/filepath"

	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/paths"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

// Table resolves interpolation names: host shell (full environ) >
// --env-file / COMPOSE_ENV_FILES (later overlay wins). Explicit --env-file
// replaces COMPOSE_ENV_FILES. Project .env is used only when that selected
// set is empty (engine replace).
type Table struct {
	host   map[string]string
	layers [][]envsrc.Binding
	fp     *redact.Fingerprinter
	files  []string
	budget *safety.Budget
	scope  *envsrc.ExpandScope
}

func Load(projectDir string, envFiles []string, cwd string, environ []string, fp *redact.Fingerprinter, budget ...*safety.Budget) (*Table, error) {
	if fp == nil {
		return nil, fmt.Errorf("fingerprint key generation failed")
	}
	bgt := safety.Optional(budget)
	t := &Table{host: envsrc.HostMap(environ), fp: fp, budget: bgt, scope: envsrc.NewExpandScope(environ)}
	extras := envsrc.ReplacementEnvFiles(envFiles, environ)
	if len(extras) == 0 {
		envPath := filepath.Join(projectDir, ".env")
		if st, err := os.Stat(envPath); err == nil && !st.IsDir() {
			b, err := envsrc.ParseFile(envPath, evidence.StageProject, fp, t.scope, bgt)
			if err != nil {
				return nil, err
			}
			t.layers = append(t.layers, b)
			t.files = append(t.files, envPath)
		}
	}
	for _, f := range extras {
		if err := t.addEnvFile(cwd, f); err != nil {
			return nil, err
		}
	}
	var all []envsrc.Binding
	for _, layer := range t.layers {
		all = append(all, layer...)
	}
	all = envsrc.ConfineBindings(projectDir, all)
	offset := 0
	for i, layer := range t.layers {
		t.layers[i] = all[offset : offset+len(layer)]
		offset += len(layer)
	}
	return t, nil
}

func (t *Table) addEnvFile(cwd, f string) error {
	resolved, err := paths.Resolve(cwd, f)
	if err != nil {
		return err
	}
	if _, err := os.Stat(resolved); err != nil {
		return fmt.Errorf("env-file %q: %w", f, err)
	}
	b, err := envsrc.ParseFile(resolved, evidence.StageEnvFile, t.fp, t.scope, t.budget)
	if err != nil {
		return err
	}
	t.layers = append(t.layers, b)
	t.files = append(t.files, resolved)
	return nil
}

func (t *Table) Paths() []string {
	if t == nil {
		return nil
	}
	return append([]string{}, t.files...)
}

func (t *Table) Get(key string) (string, bool, Source) {
	src := Source{Key: key}
	if t == nil {
		return "", false, src
	}
	if t.host != nil {
		if v, ok := t.host[key]; ok {
			return v, true, Source{Key: key, Stage: evidence.StageHost}
		}
	}
	for i := len(t.layers) - 1; i >= 0; i-- {
		var hit *envsrc.Binding
		for j := range t.layers[i] {
			if t.layers[i][j].Key == key {
				b := t.layers[i][j]
				hit = &b
			}
		}
		if hit != nil {
			return hit.RawValue, true, Source{Key: key, Stage: hit.Stage, Path: hit.Path, Line: hit.Line, Secret: hit.Reason != "", Reason: hit.Reason}
		}
	}
	return "", false, src
}

var _ Getter = (*Table)(nil)

func init() {
	envsrc.Expand = expandEnvValue
}

// lookupGetter adapts a plain lookup to a Getter for env-file expansion.
type lookupGetter func(key string) (string, bool)

func (l lookupGetter) Get(key string) (string, bool, Source) {
	v, ok := l(key)
	return v, ok, Source{Key: key}
}

// expandEnvValue interpolates one env-file value. The result is exact unless
// the text holds an unrecognized form or a required variable is unset.
func expandEnvValue(raw string, lookup func(key string) (string, bool)) (string, bool) {
	v := Substitute(raw, lookupGetter(lookup))
	exact := v.Certainty != evidence.Unknown && v.State != StateRequiredError
	return v.Resolved, exact
}
