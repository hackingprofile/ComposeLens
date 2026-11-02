// SPDX-License-Identifier: Apache-2.0

// Package envfile is the one bounded env-file grammar used for the project
// .env, CLI --env-file / COMPOSE_ENV_FILES and service env_file:. It follows
// what `docker compose config` (Compose v5.4.0) accepts and returns; input
// the engine refuses is refused here with a typed error, never reinterpreted.
//
// Default format:
//   - blank lines and lines whose first non-space character is # are skipped;
//   - an optional `export ` prefix; KEY=VALUE or KEY: VALUE; a key alone on
//     its line is inherited from the environment;
//   - keys use letters, digits and _ . - [ ]; any other character, or a
//     space inside the key, is an error;
//   - unquoted values run to the end of the line, a " #" starts a comment,
//     surrounding white space is trimmed, backslashes are literal;
//   - single- and double-quoted values may span lines. Inside both, \ before
//     the opening quote character yields that quote and \ before anything else
//     is kept with that character. A double-quoted value then expands \a \b
//     \f \n \r \t \v \\ \" \$ \uXXXX and \0NNN (octal); other escapes stay
//     literal. Text after a closing quote is read as the next entry;
//   - an unterminated quote is an error.
//
// Raw format (env_file format: raw): every non-blank, non-comment line is
// KEY=VALUE with the value kept byte for byte; a key with white space or an
// empty key is an error.
package envfile

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"composelens/internal/safety"
)

// Entry is one parsed variable.
type Entry struct {
	Key   string
	Value string
	// Quote is 0 for an unquoted value, '"' or '\''. Callers interpolate
	// unquoted and double-quoted values only.
	Quote byte
	// Inherited marks a key with no value: its value comes from the
	// environment when present.
	Inherited bool
	Line      int
}

// Parse reads env-file bytes. path names the file in diagnostics only.
func Parse(raw []byte, path string, rawFormat bool) ([]Entry, error) {
	raw = bytes.TrimPrefix(raw, []byte{0xEF, 0xBB, 0xBF})
	if !utf8.Valid(raw) {
		return nil, safety.NewParseError(safety.CodeEncoding, path, "env file is not valid UTF-8")
	}
	src := strings.ReplaceAll(string(raw), "\r\n", "\n")
	if rawFormat {
		return parseRaw(src, path)
	}
	return parseDefault(src, path)
}

func syntaxErr(path string, line int, msg string) error {
	return safety.NewParseError(safety.CodeEnvSyntax, path, fmt.Sprintf("line %d: %s", line, msg))
}

func isSpace(r rune) bool {
	switch r {
	case ' ', '\t', '\v', '\f', '\r', 0x85, 0xA0:
		return true
	}
	return false
}

func keyRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsNumber(r) || strings.ContainsRune("_.-[]", r)
}

func parseDefault(src, path string) ([]Entry, error) {
	var out []Entry
	line := 1
	i := 0
	for i < len(src) {
		// skip white space and newlines between entries
		r, w := utf8.DecodeRuneInString(src[i:])
		if r == '\n' {
			line++
			i += w
			continue
		}
		if isSpace(r) {
			i += w
			continue
		}
		if r == '#' {
			if j := strings.IndexByte(src[i:], '\n'); j >= 0 {
				i += j
			} else {
				i = len(src)
			}
			continue
		}
		if strings.HasPrefix(src[i:], "export") && i+6 < len(src) && (src[i+6] == ' ' || src[i+6] == '\t') {
			i += 6
			for i < len(src) && (src[i] == ' ' || src[i] == '\t') {
				i++
			}
			continue
		}
		// key
		keyLine := line
		j := i
		sep := byte(0)
		for j < len(src) {
			kr, kw := utf8.DecodeRuneInString(src[j:])
			if kr == '=' || kr == ':' || kr == '\n' {
				sep = byte(kr)
				break
			}
			if !isSpace(kr) && !keyRune(kr) {
				return nil, syntaxErr(path, keyLine, fmt.Sprintf("unexpected character %q in variable name", string(kr)))
			}
			j += kw
		}
		key := strings.TrimRightFunc(src[i:j], isSpace)
		if strings.IndexFunc(key, isSpace) >= 0 {
			return nil, syntaxErr(path, keyLine, "key cannot contain a space")
		}
		if sep == 0 || sep == '\n' {
			if key != "" && key != "export" {
				out = append(out, Entry{Key: key, Inherited: true, Line: keyLine})
			}
			i = j
			continue
		}
		if key == "" {
			return nil, safety.NewParseError(safety.CodeEnvUnsupported, path, fmt.Sprintf("line %d: an empty variable name is not supported", keyLine))
		}
		i = j + 1
		for i < len(src) {
			vr, vw := utf8.DecodeRuneInString(src[i:])
			if !isSpace(vr) {
				break
			}
			i += vw
		}
		if i < len(src) && (src[i] == '"' || src[i] == '\'') {
			q := src[i]
			val, next, lines, ok := extractQuoted(src, i)
			if !ok {
				return nil, syntaxErr(path, keyLine, "unterminated quoted value")
			}
			if q == '"' {
				val = expandEscapes(val)
			}
			out = append(out, Entry{Key: key, Value: val, Quote: q, Line: keyLine})
			line += lines
			i = next
			continue
		}
		end := strings.IndexByte(src[i:], '\n')
		var val string
		if end < 0 {
			val = src[i:]
			i = len(src)
		} else {
			val = src[i : i+end]
			i += end
		}
		if c := strings.Index(val, " #"); c >= 0 {
			val = val[:c]
		}
		val = strings.TrimRightFunc(val, unicode.IsSpace)
		out = append(out, Entry{Key: key, Value: val, Line: keyLine})
	}
	return out, nil
}

// extractQuoted reads the quoted value opening at src[start]. It returns the
// value, the offset after the closing quote, the newlines crossed, and false
// when the quote is not terminated.
func extractQuoted(src string, start int) (string, int, int, bool) {
	q := src[start]
	var b strings.Builder
	lines := 0
	for k := start + 1; k < len(src); k++ {
		c := src[k]
		if c == '\n' {
			lines++
		}
		if c == '\\' && k+1 < len(src) {
			n := src[k+1]
			if n == q {
				b.WriteByte(q)
			} else {
				b.WriteByte('\\')
				b.WriteByte(n)
				if n == '\n' {
					lines++
				}
			}
			k++
			continue
		}
		if c == q {
			return b.String(), k + 1, lines, true
		}
		b.WriteByte(c)
	}
	return "", 0, 0, false
}

// expandEscapes applies the double-quoted escape set. `\$` becomes `$$`, the
// interpolation escape for a literal dollar.
func expandEscapes(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		n := s[i+1]
		switch n {
		case 'a':
			b.WriteByte('\a')
		case 'b':
			b.WriteByte('\b')
		case 'f':
			b.WriteByte('\f')
		case 'n':
			b.WriteByte('\n')
		case 'r':
			b.WriteByte('\r')
		case 't':
			b.WriteByte('\t')
		case 'v':
			b.WriteByte('\v')
		case '\\':
			b.WriteByte('\\')
		case '"':
			b.WriteByte('"')
		case '$':
			b.WriteString("$$")
		case 'u':
			if i+6 <= len(s) {
				if v, err := strconv.ParseUint(s[i+2:i+6], 16, 32); err == nil && utf8.ValidRune(rune(v)) {
					b.WriteRune(rune(v))
					i += 5
					continue
				}
			}
			b.WriteString(`\u`)
		case '0':
			// \0 followed by up to three digits: the engine drops the 0 and
			// reads \DDD as an octal escape; otherwise the text stays literal.
			j := i + 2
			for j < len(s) && j < i+5 && s[j] >= '0' && s[j] <= '9' {
				j++
			}
			digits := s[i+2 : j]
			if v, err := strconv.ParseUint(digits, 8, 8); err == nil && len(digits) == 3 {
				b.WriteByte(byte(v))
			} else {
				b.WriteByte('\\')
				b.WriteString(digits)
			}
			i = j - 1
			continue
		default:
			b.WriteByte('\\')
			b.WriteByte(n)
		}
		i++
	}
	return b.String()
}

func parseRaw(src, path string) ([]Entry, error) {
	var out []Entry
	for n, text := range strings.Split(src, "\n") {
		line := n + 1
		text = strings.TrimRight(text, "\r")
		t := strings.TrimLeftFunc(text, unicode.IsSpace)
		if t == "" || strings.HasPrefix(t, "#") {
			continue
		}
		key, val, ok := strings.Cut(t, "=")
		if !ok {
			out = append(out, Entry{Key: strings.TrimRightFunc(t, unicode.IsSpace), Inherited: true, Line: line})
			continue
		}
		if key == "" {
			return nil, syntaxErr(path, line, "no variable name")
		}
		if strings.IndexFunc(key, unicode.IsSpace) >= 0 {
			return nil, syntaxErr(path, line, "variable name contains white space")
		}
		out = append(out, Entry{Key: key, Value: val, Line: line})
	}
	return out, nil
}

// Unquote returns the value of the quoted string that opens at s[0], with
// the same rules as a quoted env-file value, or false when s does not open
// with a quote or the quote is not terminated.
func Unquote(s string) (string, bool) {
	if len(s) < 2 || (s[0] != '"' && s[0] != '\'') {
		return "", false
	}
	val, _, _, ok := extractQuoted(s, 0)
	if !ok {
		return "", false
	}
	if s[0] == '"' {
		val = expandEscapes(val)
	}
	return val, true
}
