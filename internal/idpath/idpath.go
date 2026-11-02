// SPDX-License-Identifier: Apache-2.0

// Package idpath is the single reversible service-identity / path vocabulary.
// Public path strings stay services.<name>.<field…> (byte-identical for
// dotless names). Parsing uses the known service set (longest exact match)
// so a legal dotted name such as web.api does not truncate to web.
package idpath

import (
	"sort"
	"strings"
)

const Root = "services."

// Parse splits a ComposeLens path into (service, rest) losslessly when known
// contains the service name. rest includes a leading "." or "[".
// With no matching known name, it falls back to the first "." / "[" token
// (correct for dotless names; insufficient for dotted names).
func Parse(path string, known []string) (service, rest string, ok bool) {
	if !strings.HasPrefix(path, Root) {
		return "", "", false
	}
	body := path[len(Root):]
	if body == "" {
		return "", "", false
	}
	if name := longest(body, known); name != "" {
		return name, body[len(name):], true
	}
	end := len(body)
	if i := strings.IndexByte(body, '.'); i >= 0 && i < end {
		end = i
	}
	if i := strings.IndexByte(body, '['); i >= 0 && i < end {
		end = i
	}
	if end == 0 {
		return "", "", false
	}
	return body[:end], body[end:], true
}

func longest(body string, known []string) string {
	best := ""
	for _, n := range known {
		if n == "" {
			continue
		}
		if body == n || strings.HasPrefix(body, n+".") || strings.HasPrefix(body, n+"[") {
			if len(n) > len(best) {
				best = n
			}
		}
	}
	return best
}

// Join builds services.<service> or services.<service>.<field>.
func Join(service, field string) string {
	if field == "" {
		return Root + service
	}
	return Root + service + "." + field
}

// Service is Parse's service component (empty if not a services path).
func Service(path string, known []string) string {
	s, _, ok := Parse(path, known)
	if !ok {
		return ""
	}
	return s
}

// Unique sorts and de-duplicates non-empty names.
func Unique(names []string) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, n := range names {
		if n == "" {
			continue
		}
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Collect prefers explicit YAML/mapping identities. If none are present
// (hand-built test fields), it infers from paths with the first-token fallback.
func Collect(explicit []string, paths []string) []string {
	if u := Unique(explicit); len(u) > 0 {
		return u
	}
	var inferred []string
	for _, p := range paths {
		if s, _, ok := Parse(p, nil); ok {
			inferred = append(inferred, s)
		}
	}
	return Unique(inferred)
}

// EnvOK is the container-environment variable name class: [A-Za-z_][A-Za-z0-9_]*.
// Dots are not legal, so environment.FOO.BAR cannot be an env-key truncation.
func EnvOK(s string) bool {
	if s == "" {
		return false
	}
	for i, r := range s {
		letter := (r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || r == '_'
		digit := r >= '0' && r <= '9'
		if !letter && (i == 0 || !digit) {
			return false
		}
	}
	return true
}
