// SPDX-License-Identifier: Apache-2.0

package envsrc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"composelens/internal/envfile"
	"composelens/internal/evidence"
	"composelens/internal/paths"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

var HostAllowlist = []string{
	"COMPOSE_FILE",
	"COMPOSE_PROJECT_NAME",
	"COMPOSE_PROJECT_DIR",
	"COMPOSE_PROFILES",
	"COMPOSE_ENV_FILES",
	"COMPOSE_IGNORE_ORPHANS",
	"COMPOSE_CONVERT_WINDOWS_PATHS",
	"COMPOSE_PARALLEL_LIMIT",
	"COMPOSE_ANSI",
	"COMPOSE_STATUS_STDOUT",
	"COMPOSE_PROGRESS",
	"DOCKER_HOST",
	"DOCKER_CONTEXT",
	"DOCKER_CERT_PATH",
	"DOCKER_TLS_VERIFY",
	"DOCKER_API_VERSION",
}

type Binding struct {
	Key         string
	RawValue    string
	Stage       string
	Path        string
	Line        int
	Secret      bool
	Fingerprint string
	Certainty   string
	Reason      string
}

// ReplacementEnvFiles is the effective selected env-file set.
// Explicit --env-file flags fully replace COMPOSE_ENV_FILES (same overlay as
// Docker Compose). Otherwise COMPOSE_ENV_FILES is used, in given order, later
// overlay wins. An empty result means the project .env is selected.
func ReplacementEnvFiles(envFiles []string, environ []string) []string {
	var out []string
	for _, f := range envFiles {
		if strings.TrimSpace(f) != "" {
			out = append(out, f)
		}
	}
	if len(out) > 0 {
		return out
	}
	return ComposeEnvFileList(environ)
}

// UnappliedProjectEnv returns the project .env path when that file exists but is
// not in the selected interpolation set. The file is not read. An explicitly
// selected project .env is not unapplied.
func UnappliedProjectEnv(projectDir string, envFiles []string, cwd string, environ []string) (string, bool) {
	selected := ReplacementEnvFiles(envFiles, environ)
	if len(selected) == 0 {
		return "", false
	}
	envPath := filepath.Join(projectDir, ".env")
	st, err := os.Stat(envPath)
	if err != nil || st.IsDir() {
		return "", false
	}
	abs, err := paths.Canonical(envPath)
	if err != nil {
		abs = envPath
	}
	base := cwd
	if strings.TrimSpace(base) == "" {
		base = projectDir
	}
	for _, f := range selected {
		if sameSelectedPath(base, f, abs) {
			return "", false
		}
		if base != projectDir && sameSelectedPath(projectDir, f, abs) {
			return "", false
		}
	}
	return abs, true
}

func sameSelectedPath(base, rel, want string) bool {
	resolved, err := paths.Resolve(base, rel)
	if err != nil {
		return false
	}
	a := filepath.Clean(resolved)
	b := filepath.Clean(want)
	if a == b || strings.EqualFold(a, b) {
		return true
	}
	sa, err1 := os.Stat(a)
	sb, err2 := os.Stat(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return os.SameFile(sa, sb)
}

func Collect(projectDir string, envFiles []string, cwd string, environ []string, fp *redact.Fingerprinter, budget ...*safety.Budget) ([]Binding, error) {
	if fp == nil {
		return nil, fmt.Errorf("fingerprint key generation failed")
	}
	bgt := safety.Optional(budget)
	var out []Binding
	out = append(out, collectHost(environ, fp)...)
	scope := NewExpandScope(environ)
	extras := ReplacementEnvFiles(envFiles, environ)
	if len(extras) == 0 {
		envPath := filepath.Join(projectDir, ".env")
		if st, err := os.Stat(envPath); err == nil && !st.IsDir() {
			b, err := parseFile(envPath, evidence.StageProject, fp, bgt, scope)
			if err != nil {
				return nil, err
			}
			out = append(out, b...)
		}
		return ConfineBindings(projectDir, out), nil
	}
	for _, f := range extras {
		resolved, err := paths.Resolve(cwd, f)
		if err != nil {
			return nil, err
		}
		if _, err := os.Stat(resolved); err != nil {
			return nil, fmt.Errorf("env-file %q: %w", f, err)
		}
		b, err := parseFile(resolved, evidence.StageEnvFile, fp, bgt, scope)
		if err != nil {
			return nil, err
		}
		out = append(out, b...)
	}
	return ConfineBindings(projectDir, out), nil
}

// OutsideReason explains withholding values from selected interpolation files.
const OutsideReason = "environment file is outside the project directory; its values are withheld"

// ConfineBindings preserves values for resolution while marking outside
// sources and values derived from them as secret.
func ConfineBindings(root string, bindings []Binding) []Binding {
	out := append([]Binding(nil), bindings...)
	var outside []string
	for i := range out {
		if out[i].Path != "" && !paths.Within(root, out[i].Path) {
			out[i].Secret = true
			out[i].Reason = OutsideReason
			if out[i].RawValue != "" {
				outside = append(outside, out[i].RawValue)
			}
		}
	}
	for i := range out {
		for _, value := range outside {
			if strings.Contains(out[i].RawValue, value) {
				out[i].Secret = true
				out[i].Reason = OutsideReason
			}
		}
	}
	return out
}

func collectHost(environ []string, fp *redact.Fingerprinter) []Binding {
	env := parseEnviron(environ)
	var out []Binding
	for _, k := range HostAllowlist {
		v, ok := env[k]
		if !ok {
			continue
		}
		out = append(out, bind(k, v, evidence.StageHost, "", 0, evidence.Proven, fp))
	}
	return out
}

func parseEnviron(environ []string) map[string]string {
	m := map[string]string{}
	for _, kv := range environ {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		m[kv[:i]] = kv[i+1:]
	}
	return m
}

// ParseFile reads one env file. Collect remains allowlist-only for inspect;
// interpolation uses this helper plus the full host environment for name lookup.
func ParseFile(path, stage string, fp *redact.Fingerprinter, scope *ExpandScope, budget ...*safety.Budget) ([]Binding, error) {
	return parseFile(path, stage, fp, safety.Optional(budget), scope)
}

// HostMap is the full process environment (not the inspect allowlist).
func HostMap(environ []string) map[string]string {
	return parseEnviron(environ)
}

// ComposeEnvFileList returns COMPOSE_ENV_FILES entries.
// Compose uses a comma-separated list on every platform (not os.PathListSeparator).
func ComposeEnvFileList(environ []string) []string {
	v, ok := parseEnviron(environ)["COMPOSE_ENV_FILES"]
	if !ok || strings.TrimSpace(v) == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(v, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func parseFile(path, stage string, fp *redact.Fingerprinter, b *safety.Budget, scope *ExpandScope) ([]Binding, error) {
	abs, err := paths.Canonical(path)
	if err != nil {
		return nil, err
	}
	raw, err := safety.ReadCharged(b, abs, safety.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	// One env grammar for .env, --env-file and service env_file (internal/envfile).
	// A key alone on its line is inherited by the engine; it carries no value
	// here, so it is not collected.
	entries, err := envfile.Parse(raw, abs, false)
	if err != nil {
		return nil, err
	}
	var out []Binding
	for _, e := range entries {
		if e.Inherited {
			continue
		}
		val, certainty := scope.expand(e)
		out = append(out, bind(e.Key, val, stage, abs, e.Line, certainty, fp))
	}
	return out, nil
}

func bind(key, val, stage, path string, line int, certainty string, fp *redact.Fingerprinter) Binding {
	return Binding{
		Key:         key,
		RawValue:    val,
		Stage:       stage,
		Path:        path,
		Line:        line,
		Secret:      redact.MustRedact(key, val),
		Fingerprint: fp.Fingerprint(val),
		Certainty:   certainty,
	}
}

func SecretValues(bindings []Binding) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, b := range bindings {
		if !b.Secret {
			continue
		}
		for _, frag := range redact.SecretFragments(b.RawValue) {
			add(frag)
		}
	}
	return out
}

// MarkSecretKeys returns a copy of bindings in which every binding whose key
// is in keys is secret. A variable with a neutral name becomes secret when its
// value feeds a secret position, such as a field under a secret-named key.
func MarkSecretKeys(bindings []Binding, keys map[string]bool) []Binding {
	out := make([]Binding, len(bindings))
	copy(out, bindings)
	for i := range out {
		if keys[out[i].Key] {
			out[i].Secret = true
		}
	}
	return out
}

// Expand interpolates one env-file value with lookup, as Compose does, and
// reports whether the result is exact. internal/interp installs it; when it
// is nil, values are kept as written.
var Expand func(raw string, lookup func(key string) (string, bool)) (string, bool)

// ExpandScope is the variable scope for the selected env files of one run.
// Compose expands an unquoted or double-quoted value with the process
// environment first, then every earlier entry of this and earlier files; a
// single-quoted value is literal. A nil scope keeps values as written.
type ExpandScope struct {
	host  map[string]string
	prior map[string]string
}

// NewExpandScope starts a scope over the process environment.
func NewExpandScope(environ []string) *ExpandScope {
	return &ExpandScope{host: parseEnviron(environ), prior: map[string]string{}}
}

func (s *ExpandScope) lookup(key string) (string, bool) {
	if v, ok := s.host[key]; ok {
		return v, true
	}
	v, ok := s.prior[key]
	return v, ok
}

func (s *ExpandScope) expand(e envfile.Entry) (string, string) {
	if s == nil {
		return e.Value, evidence.Proven
	}
	val, certainty := e.Value, evidence.Proven
	if Expand != nil && e.Quote != '\'' && strings.Contains(val, "$") {
		out, exact := Expand(val, s.lookup)
		val = out
		if !exact {
			certainty = evidence.Unknown
		}
	}
	s.prior[e.Key] = val
	return val, certainty
}
