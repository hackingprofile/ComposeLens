// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"regexp"
	"strings"
)

// composeResourceSections are top-level Compose sections whose second path
// segment is a user-chosen resource name (a service, network, volume, config
// or secret definition). The section and the name identify a resource; they
// do not say what the values under them are.
var composeResourceSections = map[string]struct{}{
	"services": {}, "networks": {}, "volumes": {}, "configs": {}, "secrets": {},
}

// SecretPath reports whether a dotted ComposeLens path such as
// "x-credentials.api_token.value" or "services.api.x-auth.password.current"
// runs through a secret-named mapping key at any depth. A value under such a
// key is a secret even when its own leaf key is neutral.
//
// Compose structure is not treated as a secret name: the top-level section,
// the resource name under services/networks/volumes/configs/secrets, and the
// "secrets" reference lists of a service or its build section.
func SecretPath(path string) bool {
	segs := pathKeys(path)
	if len(segs) >= 3 && segs[2] == "content" {
		if segs[0] == "secrets" || (segs[0] == "configs" && IsSecretKey(segs[1])) {
			return true
		}
	}
	for i, seg := range segs {
		if structuralSegment(segs, i) {
			continue
		}
		if IsSecretKey(seg) {
			return true
		}
	}
	return false
}

// MustRedactAt is MustRedact with the whole path of the value as context.
func MustRedactAt(path, value string) bool {
	if publicSignal(path, value) {
		return false
	}
	if !SecretPath(path) && publicRevision(path, value) {
		return false
	}
	return SecretPath(path) || LooksLikeSecret(value)
}

func structuralSegment(segs []string, i int) bool {
	if len(segs) == 0 {
		return false
	}
	_, section := composeResourceSections[segs[0]]
	switch i {
	case 0:
		return section || segs[0] == "include" || segs[0] == "name" || segs[0] == "version"
	case 1:
		return section
	}
	if segs[0] != "services" {
		return false
	}
	if i == 2 && segs[2] == "secrets" {
		return true
	}
	if i == 3 && (segs[2] == "depends_on" || segs[2] == "networks") {
		return true
	}
	return i == 3 && segs[2] == "build" && segs[3] == "secrets"
}

// pathKeys splits a dotted path into mapping keys, dropping sequence indexes
// such as "[0]".
func pathKeys(path string) []string {
	if path == "" {
		return nil
	}
	raw := strings.Split(path, ".")
	out := make([]string, 0, len(raw))
	for _, seg := range raw {
		if i := strings.IndexByte(seg, '['); i >= 0 {
			seg = seg[:i]
		}
		if seg != "" {
			out = append(out, seg)
		}
	}
	return out
}

// RawReferenceShowable reports whether the raw, uninterpolated form of a
// withheld value may be shown: it references a variable ("-p${DB_PASSWORD}"),
// its path is not secret-named and its own text is not secret-shaped, so it
// names the variable without its value.
func RawReferenceShowable(path, raw string) bool {
	if !strings.Contains(raw, "$") || SecretPath(path) || LooksLikeSecret(raw) {
		return false
	}
	// Only plain references: a default or alternate (${TOKEN:-literal})
	// carries literal text that may itself be the secret.
	rest := rePlainRef.ReplaceAllString(strings.ReplaceAll(raw, "$$", ""), "")
	return !strings.Contains(rest, "$")
}

var rePlainRef = regexp.MustCompile(`\$(?:\{[A-Za-z_][A-Za-z0-9_]*\}|[A-Za-z_][A-Za-z0-9_]*)`)
