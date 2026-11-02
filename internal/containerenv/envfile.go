// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"strings"

	"composelens/internal/envfile"
	"composelens/internal/interp"
	"composelens/internal/paths"
	"composelens/internal/safety"
)

type fileEntry struct {
	Key   string
	Value string
	Unset bool
	Line  int
}

// readEnvFile parses a service env_file with the shared env grammar
// (internal/envfile). format raw keeps values byte for byte; otherwise
// unquoted and double-quoted values are interpolated with g.
func readEnvFile(path, format string, g interp.Getter, b *safety.Budget) ([]fileEntry, error) {
	chargePath := path
	if abs, err := paths.Canonical(path); err == nil {
		chargePath = abs
	}
	raw, err := safety.ReadCharged(b, chargePath, safety.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	rawFormat := format == "raw"
	entries, err := envfile.Parse(raw, path, rawFormat)
	if err != nil {
		return nil, err
	}
	out := make([]fileEntry, 0, len(entries))
	// Compose expands a value with the project environment first, then the
	// earlier entries of the same file.
	local := map[string]string{}
	scope := fileScope{g: g, local: local}
	for _, e := range entries {
		if e.Inherited {
			out = append(out, fileEntry{Key: e.Key, Unset: true, Line: e.Line})
			continue
		}
		val := e.Value
		if !rawFormat && e.Quote != '\'' && g != nil && strings.Contains(val, "$") {
			val = interp.Substitute(val, scope).Resolved
		}
		local[e.Key] = val
		out = append(out, fileEntry{Key: e.Key, Value: val, Line: e.Line})
	}
	return out, nil
}

// unquoteEnv unquotes one quoted env-file value (shared grammar).
func unquoteEnv(s string) (string, bool) {
	return envfile.Unquote(s)
}

// fileScope looks a variable up in the project environment, then in the
// earlier entries of the env_file being read.
type fileScope struct {
	g     interp.Getter
	local map[string]string
}

func (s fileScope) Get(key string) (string, bool, interp.Source) {
	if s.g != nil {
		if v, ok, src := s.g.Get(key); ok {
			return v, ok, src
		}
	}
	v, ok := s.local[key]
	return v, ok, interp.Source{Key: key}
}
