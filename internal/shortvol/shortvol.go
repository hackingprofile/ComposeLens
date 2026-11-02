// SPDX-License-Identifier: Apache-2.0

// Package shortvol is the single drive-aware parser for Compose short-volume
// syntax [SOURCE:]TARGET[:MODE]. A Windows drive prefix (letter + ':' + '\'
// or '/') is part of SOURCE, not a field separator. Merge, extends, and
// normalize all key and canonicalize volumes through Parse.
package shortvol

import "strings"

// Spec is one short-volume triple. Target is the container path used as the
// unique overlay key.
type Spec struct {
	Source string
	Target string
	Mode   string
}

// Parse splits a short volume string. Long-form mapping YAML is not accepted.
func Parse(raw string) (Spec, bool) {
	spec := strings.TrimSpace(raw)
	if spec == "" || strings.HasPrefix(spec, "{") {
		return Spec{}, false
	}
	parts := splitColons(spec)
	switch len(parts) {
	case 1:
		if parts[0] == "" {
			return Spec{}, false
		}
		return Spec{Target: parts[0]}, true
	case 2:
		if parts[1] == "" {
			return Spec{}, false
		}
		return Spec{Source: parts[0], Target: parts[1]}, true
	case 3:
		if parts[1] == "" {
			return Spec{}, false
		}
		return Spec{Source: parts[0], Target: parts[1], Mode: parts[2]}, true
	default:
		return Spec{}, false
	}
}

// Target is the container path used for unique-key overlay. Empty if unparseable.
func Target(raw string) string {
	s, ok := Parse(raw)
	if !ok {
		return ""
	}
	return s.Target
}

// WindowsDrive reports whether source begins with a Windows drive prefix
// (C:\, D:/, or a bare C:).
func WindowsDrive(source string) bool {
	if len(source) < 2 {
		return false
	}
	c := source[0]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	if source[1] != ':' {
		return false
	}
	if len(source) == 2 {
		return true
	}
	return source[2] == '\\' || source[2] == '/'
}

func splitColons(spec string) []string {
	var parts []string
	start := 0
	for i := 0; i < len(spec); i++ {
		if spec[i] != ':' {
			continue
		}
		if isWindowsDriveColon(spec, start, i) {
			continue
		}
		parts = append(parts, spec[start:i])
		start = i + 1
	}
	parts = append(parts, spec[start:])
	return parts
}

func isWindowsDriveColon(spec string, start, colon int) bool {
	if colon != start+1 {
		return false
	}
	c := spec[start]
	if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') {
		return false
	}
	if colon+1 >= len(spec) {
		return true
	}
	n := spec[colon+1]
	return n == '\\' || n == '/'
}
