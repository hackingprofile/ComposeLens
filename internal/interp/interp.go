// SPDX-License-Identifier: Apache-2.0

package interp

import (
	"strings"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/evidence"
	"composelens/internal/redact"
)

const (
	StateResolved       = "resolved"
	StateDefaulted      = "defaulted"
	StateAbsentEmpty    = "absent-empty"
	StateRequiredError  = "required-error"
	StateEscapedLiteral = "escaped-literal"
	// StateInvalid is a braced form Compose rejects (${}, ${1A}, ${A:0:2}, an
	// unclosed ${A). Compose refuses the whole file; ComposeLens keeps the raw
	// text, marks the value unknown and check reports it as an error.
	StateInvalid = "invalid-format"

	// InvalidFormatMessage is the diagnostic for StateInvalid.
	InvalidFormatMessage = "invalid interpolation format; Compose rejects this file (escape a literal $ as $$)"

	FormBare          = "$VAR"
	FormBrace         = "${VAR}"
	FormDefaultEmpty  = "${VAR:-default}"
	FormDefaultUnset  = "${VAR-default}"
	FormRequiredEmpty = "${VAR:?err}"
	FormRequiredUnset = "${VAR?err}"
	FormAltNonEmpty   = "${VAR:+replacement}"
	FormAltSet        = "${VAR+replacement}"
	FormEscape        = "$$"
	FormMixed         = "mixed"
	FormUnrecognized  = "unrecognized-dollar"
)

type Source struct {
	Key    string `json:"key"`
	Stage  string `json:"stage,omitempty"`
	Path   string `json:"path,omitempty"`
	Line   int    `json:"line,omitempty"`
	Secret bool   `json:"secret,omitempty"`
	Reason string `json:"reason,omitempty"`
}

type Getter interface {
	Get(key string) (value string, present bool, src Source)
}

type Variable struct {
	Key     string  `json:"key"`
	Form    string  `json:"form"`
	Stage   string  `json:"stage,omitempty"`
	Path    *string `json:"path"`
	Line    *int    `json:"line"`
	Present bool    `json:"present"`
}

type Value struct {
	Path        string                `json:"path"`
	Location    composeparse.Location `json:"location"`
	Raw         string                `json:"raw"`
	Resolved    string                `json:"-"`
	Form        string                `json:"form"`
	State       string                `json:"state"`
	Source      *Source               `json:"source"`
	Variables   []Variable            `json:"variables"`
	Error       string                `json:"error,omitempty"`
	Secret      bool                  `json:"secret"`
	Fingerprint string                `json:"fingerprint,omitempty"`
	Certainty   string                `json:"certainty"`
	Evidence    string                `json:"evidence"`
}

type piece struct {
	text    string
	form    string
	state   string
	err     string
	src     Source
	hasSrc  bool
	unknown bool
	// nested lists the variables referenced inside default or alternate text.
	nested []Variable
}

// maxNesting bounds nested defaults such as ${A:-${B:-${C}}}. Deeper text is
// kept as written and the value is marked unknown.
const maxNesting = 8

func Substitute(raw string, g Getter) Value {
	return substitute(raw, g, 0)
}

func substitute(raw string, g Getter, depth int) Value {
	v := Value{
		Raw:       raw,
		Evidence:  evidence.Known,
		Certainty: evidence.Proven,
	}
	if !strings.Contains(raw, "$") {
		v.Resolved = raw
		v.State = StateResolved
		v.Form = ""
		return v
	}
	var pieces []piece
	i := 0
	for i < len(raw) {
		if raw[i] != '$' {
			j := i + 1
			for j < len(raw) && raw[j] != '$' {
				j++
			}
			pieces = append(pieces, piece{text: raw[i:j], form: "", state: ""})
			i = j
			continue
		}
		p, n := next(raw[i:], g, depth)
		pieces = append(pieces, p)
		i += n
	}
	return combine(v, pieces, g)
}

func next(s string, g Getter, depth int) (piece, int) {
	if len(s) >= 2 && s[0] == '$' && s[1] == '$' {
		return piece{text: "$", form: FormEscape, state: StateEscapedLiteral}, 2
	}
	if len(s) >= 2 && s[1] == '{' {
		return braced(s, g, depth)
	}
	if len(s) >= 2 && nameStart(s[1]) {
		j := 1
		for j < len(s) && namePart(s[j]) {
			j++
		}
		key := s[1:j]
		return simple(key, FormBare, g), j
	}
	return piece{text: "$", form: FormUnrecognized, state: StateEscapedLiteral, unknown: true}, 1
}

func braced(s string, g Getter, depth int) (piece, int) {
	end := closingBrace(s)
	if end < 0 {
		return piece{text: s, form: FormUnrecognized, state: StateInvalid, unknown: true}, len(s)
	}
	body := s[2:end]
	consumed := end + 1
	if body == "" {
		return piece{text: s[:consumed], form: FormUnrecognized, state: StateInvalid, unknown: true}, consumed
	}
	i := 0
	for i < len(body) && namePart(body[i]) {
		i++
	}
	if i == 0 || !nameStart(body[0]) {
		return piece{text: s[:consumed], form: FormUnrecognized, state: StateInvalid, unknown: true}, consumed
	}
	key := body[:i]
	op := body[i:]
	switch {
	case op == "":
		return simple(key, FormBrace, g), consumed
	case strings.HasPrefix(op, ":-"):
		return withDefault(key, op[2:], FormDefaultEmpty, true, g, depth), consumed
	case strings.HasPrefix(op, ":?"):
		return required(key, op[2:], FormRequiredEmpty, true, g), consumed
	case strings.HasPrefix(op, ":+"):
		return alternate(key, op[2:], FormAltNonEmpty, true, g, depth), consumed
	case strings.HasPrefix(op, "-"):
		return withDefault(key, op[1:], FormDefaultUnset, false, g, depth), consumed
	case strings.HasPrefix(op, "?"):
		return required(key, op[1:], FormRequiredUnset, false, g), consumed
	case strings.HasPrefix(op, "+"):
		return alternate(key, op[1:], FormAltSet, false, g, depth), consumed
	default:
		return piece{text: s[:consumed], form: FormUnrecognized, state: StateInvalid, unknown: true}, consumed
	}
}

func simple(key, form string, g Getter) piece {
	val, ok, src := g.Get(key)
	if src.Key == "" {
		src.Key = key
	}
	p := piece{form: form, src: src, hasSrc: ok}
	if !ok || val == "" {
		p.text = ""
		p.state = StateAbsentEmpty
		return p
	}
	p.text = val
	p.state = StateResolved
	return p
}

func withDefault(key, def, form string, emptyToo bool, g Getter, depth int) piece {
	val, ok, src := g.Get(key)
	if src.Key == "" {
		src.Key = key
	}
	p := piece{form: form, src: src, hasSrc: ok}
	useDef := !ok || (emptyToo && val == "")
	if useDef {
		p.state = StateDefaulted
		expandInto(&p, def, g, depth)
		return p
	}
	p.text = val
	p.state = StateResolved
	return p
}

func required(key, msg, form string, emptyToo bool, g Getter) piece {
	val, ok, src := g.Get(key)
	if src.Key == "" {
		src.Key = key
	}
	p := piece{form: form, src: src, hasSrc: ok}
	fail := !ok || (emptyToo && val == "")
	if fail {
		if msg == "" {
			msg = key + " is required for interpolation"
		}
		p.state = StateRequiredError
		p.err = msg
		p.text = ""
		return p
	}
	p.text = val
	p.state = StateResolved
	return p
}

func alternate(key, repl, form string, nonEmpty bool, g Getter, depth int) piece {
	val, ok, src := g.Get(key)
	if src.Key == "" {
		src.Key = key
	}
	p := piece{form: form, src: src, hasSrc: ok}
	use := ok
	if nonEmpty {
		use = ok && val != ""
	}
	if use {
		p.state = StateResolved
		expandInto(&p, repl, g, depth)
		return p
	}
	p.text = ""
	p.state = StateAbsentEmpty
	return p
}

func combine(v Value, pieces []piece, g Getter) Value {
	forms := map[string]struct{}{}
	states := map[string]struct{}{}
	var b strings.Builder
	unknown := false
	var firstSrc *Source
	for _, p := range pieces {
		if p.form != "" {
			forms[p.form] = struct{}{}
		}
		if p.state == StateInvalid {
			v.State = StateInvalid
			v.Form = FormUnrecognized
			v.Resolved = v.Raw
			v.Error = InvalidFormatMessage
			v.Certainty = evidence.Unknown
			v.Variables = variables(pieces)
			applySecret(&v, g)
			return v
		}
		if p.state != "" {
			states[p.state] = struct{}{}
		}
		if p.unknown {
			unknown = true
		}
		if p.state == StateRequiredError {
			v.State = StateRequiredError
			v.Error = p.err
			v.Resolved = ""
			v.Form = p.form
			if len(forms) > 1 {
				v.Form = FormMixed
			}
			if p.hasSrc || p.src.Key != "" {
				src := p.src
				if src.Key == "" {
					src.Key = variableKey(p)
				}
				v.Source = &src
			}
			v.Variables = variables(pieces)
			if unknown {
				v.Certainty = evidence.Unknown
			}
			applySecret(&v, g)
			return v
		}
		b.WriteString(p.text)
		if firstSrc == nil && p.src.Key != "" && p.form != FormEscape && p.form != FormUnrecognized {
			src := p.src
			firstSrc = &src
		}
	}
	v.Resolved = b.String()
	v.Source = firstSrc
	v.Variables = variables(pieces)
	switch {
	case len(forms) == 0:
		v.Form = ""
		v.State = StateResolved
	case len(forms) == 1:
		for f := range forms {
			v.Form = f
		}
	default:
		v.Form = FormMixed
	}
	switch {
	case hasState(states, StateDefaulted):
		v.State = StateDefaulted
	case hasState(states, StateAbsentEmpty) && !hasState(states, StateResolved):
		v.State = StateAbsentEmpty
	case hasState(states, StateEscapedLiteral) && !hasState(states, StateResolved) && !hasState(states, StateDefaulted) && !hasState(states, StateAbsentEmpty):
		v.State = StateEscapedLiteral
	default:
		v.State = StateResolved
	}
	if unknown {
		v.Certainty = evidence.Unknown
	}
	applySecret(&v, g)
	return v
}

func hasState(m map[string]struct{}, s string) bool {
	_, ok := m[s]
	return ok
}

func variableKey(p piece) string {
	return p.src.Key
}

func variables(pieces []piece) []Variable {
	var out []Variable
	for _, p := range pieces {
		if p.form == "" || p.form == FormEscape || p.form == FormUnrecognized {
			continue
		}
		vr := Variable{Key: p.src.Key, Form: p.form, Stage: p.src.Stage, Present: p.hasSrc}
		if p.src.Path != "" {
			path := p.src.Path
			vr.Path = &path
		}
		if p.src.Line > 0 {
			line := p.src.Line
			vr.Line = &line
		}
		out = append(out, vr)
		out = append(out, p.nested...)
	}
	return out
}

func applySecret(v *Value, g Getter) {
	if redact.LooksLikeSecret(v.Raw) || redact.LooksLikeSecret(v.Resolved) || redact.LooksLikeSecret(v.Error) {
		v.Secret = true
	}
	for _, vr := range v.Variables {
		if redact.IsSecretKey(vr.Key) {
			v.Secret = true
		}
		if g != nil {
			val, ok, src := g.Get(vr.Key)
			if ok && (src.Secret || redact.MustRedact(vr.Key, val)) {
				v.Secret = true
			}
		}
	}
	if redact.SecretPath(v.Path) {
		v.Secret = true
	}
}

func nameStart(b byte) bool {
	return b == '_' || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z')
}

func namePart(b byte) bool {
	return nameStart(b) || (b >= '0' && b <= '9')
}

func ResolveScalars(scalars []composeparse.Scalar, g Getter, fp *redact.Fingerprinter) []Value {
	var out []Value
	for _, s := range scalars {
		if !strings.Contains(s.Value, "$") {
			continue
		}
		v := Substitute(s.Value, g)
		v.Path = s.Path
		v.Location = s.Location
		if redact.SecretPath(v.Path) {
			v.Secret = true
		}
		if fp != nil && v.State != StateRequiredError {
			v.Fingerprint = fp.Fingerprint(v.Resolved)
		}
		out = append(out, v)
	}
	return out
}

func SecretFragments(values []Value) []string {
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
	for _, v := range values {
		if !v.Secret {
			continue
		}
		if redact.LooksLikeSecret(v.Raw) {
			for _, f := range redact.SecretFragments(v.Raw) {
				add(f)
			}
		}
		for _, def := range interpolationDefaultFragments(v.Raw) {
			add(def)
			for _, f := range redact.SecretFragments(def) {
				add(f)
			}
		}
		for _, f := range redact.SecretFragments(v.Resolved) {
			add(f)
		}
		if v.Error != "" {
			add(v.Error)
		}
	}
	return out
}

func interpolationDefaultFragments(raw string) []string {
	var out []string
	i := 0
	for i < len(raw) {
		if i < len(raw) && raw[i] == '$' && i+1 < len(raw) && raw[i+1] == '{' {
			end := strings.IndexByte(raw[i+2:], '}')
			if end < 0 {
				break
			}
			inner := raw[i+2 : i+2+end]
			if def, ok := braceDefault(inner); ok && def != "" {
				out = append(out, def)
			}
			i = i + 2 + end + 1
			continue
		}
		i++
	}
	return out
}

func braceDefault(inner string) (string, bool) {
	j := 0
	for j < len(inner) && namePart(inner[j]) {
		j++
	}
	if j == 0 || j >= len(inner) {
		return "", false
	}
	rest := inner[j:]
	switch {
	case strings.HasPrefix(rest, ":-"), strings.HasPrefix(rest, ":?"), strings.HasPrefix(rest, ":+"):
		return rest[2:], true
	case strings.HasPrefix(rest, "-"), strings.HasPrefix(rest, "?"), strings.HasPrefix(rest, "+"):
		return rest[1:], true
	}
	return "", false
}

// InterpolateTree writes resolved scalar strings into a YAML tree (in place).
// Mapping keys are not interpolated. Required-unset becomes an empty scalar.
func InterpolateTree(n *yaml.Node, g Getter) {
	n = derefNode(n)
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			InterpolateTree(n.Content[0], g)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			InterpolateTree(n.Content[i+1], g)
		}
	case yaml.SequenceNode:
		for _, c := range n.Content {
			InterpolateTree(c, g)
		}
	case yaml.ScalarNode:
		if g == nil || !stringScalar(n) || !strings.Contains(n.Value, "$") {
			return
		}
		v := Substitute(n.Value, g)
		n.Value = v.Resolved
	}
}

func derefNode(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

func stringScalar(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	switch n.Tag {
	case "!!bool", "!!int", "!!float", "!!null", "!!binary", "!!timestamp", "!!merge":
		return false
	default:
		return true
	}
}

// SecretVariableKeys lists the variables referenced by secret values. Their
// sources must be withheld wherever they are shown.
func SecretVariableKeys(values []Value) map[string]bool {
	out := map[string]bool{}
	for _, v := range values {
		if !v.Secret {
			continue
		}
		for _, vr := range v.Variables {
			if vr.Key != "" {
				out[vr.Key] = true
			}
		}
	}
	return out
}

// InterpolateTreeSecrets is InterpolateTree that also returns the values of
// the secret variables it substituted (a secret-named variable, or one whose
// value is secret-shaped). A field that embeds such a value is secret even
// when its own key is not.
func InterpolateTreeSecrets(n *yaml.Node, g Getter) []string {
	var out []string
	seen := map[*yaml.Node]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		n = derefNode(n)
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		switch n.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range n.Content {
				walk(c)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				walk(n.Content[i+1])
			}
		case yaml.ScalarNode:
			if g == nil || !stringScalar(n) || !strings.Contains(n.Value, "$") {
				return
			}
			v := Substitute(n.Value, g)
			n.Value = v.Resolved
			for _, vr := range v.Variables {
				val, ok, src := g.Get(vr.Key)
				if ok && val != "" && (src.Secret || redact.MustRedact(vr.Key, val)) {
					out = append(out, val)
				}
			}
		}
	}
	walk(n)
	return out
}

// closingBrace returns the index of the "}" that closes the "${" at the
// start of s, skipping nested "${…}" and "$$" escapes, or -1.
func closingBrace(s string) int {
	depth := 0
	for k := 2; k < len(s); k++ {
		switch {
		case s[k] == '$' && k+1 < len(s) && (s[k+1] == '{' || s[k+1] == '$'):
			if s[k+1] == '{' {
				depth++
			}
			k++
		case s[k] == '}':
			if depth == 0 {
				return k
			}
			depth--
		}
	}
	return -1
}

// expandInto interpolates default or alternate text, as Compose does, into
// p: nested references resolve, "$$" becomes "$", and a required error
// inside the text becomes the piece's error.
func expandInto(p *piece, text string, g Getter, depth int) {
	if !strings.Contains(text, "$") {
		p.text = text
		return
	}
	if depth >= maxNesting {
		p.text = text
		p.unknown = true
		return
	}
	sub := substitute(text, g, depth+1)
	p.nested = append(p.nested, sub.Variables...)
	if sub.Certainty == evidence.Unknown {
		p.unknown = true
	}
	if sub.State == StateRequiredError {
		p.state = StateRequiredError
		p.err = sub.Error
		p.text = ""
		return
	}
	p.text = sub.Resolved
}
