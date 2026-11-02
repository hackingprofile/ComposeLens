// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// EscapeControls shows characters that can drive a terminal or a CI log as
// visible escapes: CR and LF (which would start a new line, and so a GitHub
// workflow command such as "::error::"), tab and other C0 controls, DEL, C1
// controls (U+0080–U+009F), bidirectional controls and zero-width
// characters, and the Unicode line and paragraph separators. Everything else
// is unchanged. Invalid UTF-8 bytes are shown as \xNN.
func EscapeControls(s string) string {
	if !needsEscape(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n':
			b.WriteString(`\n`)
		case r == '\r':
			b.WriteString(`\r`)
		case r == '\t':
			b.WriteString(`\t`)
		case escapedRune(r):
			if r < 0x100 {
				fmt.Fprintf(&b, `\x%02x`, r)
			} else {
				fmt.Fprintf(&b, `\u%04x`, r)
			}
		default:
			b.WriteString(s[i : i+size])
		}
		i += size
	}
	return b.String()
}

// EscapeInvisibles escapes only the characters that never belong to
// ComposeLens's own text (C1, bidirectional and zero-width controls, line
// separators), keeping newlines and tabs. It is a last pass over whole human
// output; data printed into that output is escaped with EscapeControls first.
func EscapeInvisibles(s string) string {
	var b strings.Builder
	changed := false
	for i, r := range s {
		if r != '\n' && r != '\t' && r != '\r' && escapedRune(r) && r >= 0x80 {
			if !changed {
				b.Grow(len(s) + 8)
				b.WriteString(s[:i])
				changed = true
			}
			fmt.Fprintf(&b, `\u%04x`, r)
			continue
		}
		if changed {
			b.WriteRune(r)
		}
	}
	if !changed {
		return s
	}
	return b.String()
}

func needsEscape(s string) bool {
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		if (r == utf8.RuneError && size == 1) || r == '\n' || r == '\r' || r == '\t' || escapedRune(r) {
			return true
		}
		i += size
	}
	return false
}

func escapedRune(r rune) bool {
	switch {
	case r < 0x20, r == 0x7f:
		return true
	case r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r == 0x200e, r == 0x200f:
		return true
	case r >= 0x202a && r <= 0x202e:
		return true
	case r >= 0x2066 && r <= 0x2069:
		return true
	case r >= 0x200b && r <= 0x200d, r == 0x2060, r == 0xfeff:
		return true
	case r == 0x2028, r == 0x2029:
		return true
	}
	return false
}
