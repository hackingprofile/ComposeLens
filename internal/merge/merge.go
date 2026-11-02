// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/evidence"
	"composelens/internal/idpath"
	"composelens/internal/interp"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

const (
	ActionSource   = "source"
	ActionAdd      = "add"
	ActionOverride = "override"
	ActionReplace  = "replace"
	ActionAppend   = "append"
	ActionReset    = "reset"

	TagReset    = "!reset"
	TagOverride = "!override"
)

type Contributor struct {
	File   string `json:"file"`
	Line   int    `json:"line,omitempty"`
	Action string `json:"action,omitempty"`
	Value  string `json:"-"`
}

type Field struct {
	Path    string
	Service string
	Value   string
	Winner  string
	Line    int
	// Column is the winning value's column when its node is on Line (0 when
	// the winner is synthesized, e.g. an override mapping).
	Column     int
	Action     string
	Overridden []Contributor
	Certainty  string
	Evidence   string
	Secret     bool
	// Null is set when the winning value is a YAML null (`KEY:` or `KEY: ~`)
	// rather than a string; `KEY: ""` is an empty string and is not null.
	Null bool
}

type seqMeta struct {
	file      string
	line      int
	action    string
	prev      []Contributor
	certainty string
}

type val struct {
	node      *yaml.Node
	file      string
	line      int
	action    string
	prev      []Contributor
	kids      map[string]*val
	order     []string
	seqMeta   []seqMeta
	certainty string
}

func Documents(docs []*composeparse.Document, g interp.Getter) []Field {
	var acc *val
	var secretVals []string
	for _, d := range docs {
		if d == nil || d.Root == nil {
			continue
		}
		var origins map[*yaml.Node]string
		if len(d.Origins) > 0 {
			origins = map[*yaml.Node]string{}
		}
		root := cloneOrigins(d.Root, d.Origins, origins)
		// Interpolate once. Extends already substituted the tree; a second
		// InterpolateTree would expand escaped `$VAR` / `${notavar}` / `$HOME`
		// as real variables and drop the escaped-literal result.
		if g != nil && !d.Interpolated {
			secretVals = append(secretVals, interp.InterpolateTreeSecrets(root, g)...)
		}
		secretVals = append(secretVals, d.SecretValues...)
		cur := wrap(root, d.File.Path, ActionSource)
		applyOrigins(cur, origins)
		if d.Uncertain != "" {
			markUnknown(cur)
		}
		if acc == nil {
			acc = cur
			continue
		}
		acc = overlay(acc, cur, "", "")
	}
	if acc == nil {
		return nil
	}
	var out []Field
	flatten("", "", acc, &out)
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	linkSecretFlags(out)
	withholdEmbeddedSecrets(out, secretVals)
	return out
}

// ServiceNames is the canonical service set from merge fields (YAML mapping keys).
func ServiceNames(fields []Field) []string {
	var explicit, paths []string
	for _, f := range fields {
		explicit = append(explicit, f.Service)
		paths = append(paths, f.Path)
	}
	return idpath.Collect(explicit, paths)
}

func wrap(n *yaml.Node, file, action string) *val {
	n = deref(n)
	if n != nil && n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return &val{node: n, file: file, line: n.Line, action: action}
		}
		return wrap(n.Content[0], file, action)
	}
	v := &val{node: n, file: file, line: lineOf(n), action: action}
	if n != nil && n.Kind == yaml.MappingNode {
		v.kids = map[string]*val{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := deref(n.Content[i])
			if k == nil {
				continue
			}
			if _, ok := v.kids[k.Value]; !ok {
				v.order = append(v.order, k.Value)
			}
			v.kids[k.Value] = wrap(n.Content[i+1], file, ActionSource)
		}
	}
	return v
}

func overlay(base, over *val, key, path string) *val {
	if over == nil {
		return base
	}
	if base == nil {
		over.action = ActionAdd
		return over
	}
	on := deref(over.node)
	if customTag(on) == TagReset {
		return &val{
			node:   nullNode(),
			file:   over.file,
			line:   lineOf(on),
			action: ActionReset,
			prev:   lost(base),
		}
	}
	if customTag(on) == TagOverride {
		over.action = ActionOverride
		over.prev = lost(base)
		return over
	}
	bn := deref(base.node)
	if bn != nil && on != nil && bn.Kind == yaml.MappingNode && on.Kind == yaml.MappingNode {
		return mergeMaps(base, over, path)
	}
	if bn != nil && on != nil && bn.Kind == yaml.SequenceNode && on.Kind == yaml.SequenceNode {
		return overlaySequences(base, over, key, path)
	}
	over.action = ActionOverride
	over.prev = lost(base)
	if (bn != nil && bn.Kind == yaml.SequenceNode) || (on != nil && on.Kind == yaml.SequenceNode) {
		over.certainty = evidence.Unknown
	}
	return over
}

func mergeMaps(base, over *val, path string) *val {
	order := make([]string, 0, len(base.order)+len(over.order))
	seen := map[string]struct{}{}
	add := func(k string) {
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		order = append(order, k)
	}
	for _, k := range base.order {
		add(k)
	}
	for _, k := range over.order {
		add(k)
	}
	kids := make(map[string]*val, len(order))
	for _, k := range order {
		bv := base.kids[k]
		ov := over.kids[k]
		childPath := k
		if path != "" {
			childPath = path + "." + k
		}
		switch {
		case ov == nil:
			kids[k] = bv
		case bv == nil:
			ov.action = ActionAdd
			kids[k] = ov
		default:
			kids[k] = overlay(bv, ov, k, childPath)
		}
	}
	return &val{
		node:   &yaml.Node{Kind: yaml.MappingNode, Tag: "!!map"},
		file:   over.file,
		line:   over.line,
		action: ActionOverride,
		kids:   kids,
		order:  order,
	}
}

func lost(v *val) []Contributor {
	if v == nil {
		return nil
	}
	out := append([]Contributor{}, v.prev...)
	out = append(out, Contributor{File: v.file, Line: v.line, Action: v.action, Value: renderVal(v)})
	return out
}

func flatten(path, svc string, v *val, out *[]Field) {
	if v == nil {
		return
	}
	n := deref(v.node)
	if v.action == ActionReset || customTag(n) == TagReset {
		*out = append(*out, fieldFrom(path, svc, v, ""))
		return
	}
	if len(v.kids) > 0 {
		for _, k := range v.order {
			childPath := k
			if path != "" {
				childPath = path + "." + k
			}
			childSvc := svc
			if path == "services" {
				childSvc = k
			}
			flatten(childPath, childSvc, v.kids[k], out)
		}
		return
	}
	if n != nil && n.Kind == yaml.SequenceNode {
		*out = append(*out, fieldFrom(path, svc, v, render(n)))
		for i, c := range n.Content {
			idx := path + "[" + strconv.Itoa(i) + "]"
			file, action, prev, line, cert := v.file, v.action, v.prev, v.line, v.certainty
			if i < len(v.seqMeta) {
				m := v.seqMeta[i]
				file, action, prev, line = m.file, m.action, m.prev, m.line
				if m.certainty != "" {
					cert = m.certainty
				}
			}
			ch := wrap(c, file, action)
			ch.prev = prev
			ch.line = line
			ch.certainty = cert
			flatten(idx, svc, ch, out)
		}
		return
	}
	*out = append(*out, fieldFrom(path, svc, v, render(n)))
}

func fieldFrom(path, svc string, v *val, value string) Field {
	f := Field{
		Path:       path,
		Service:    svc,
		Value:      value,
		Winner:     v.file,
		Line:       v.line,
		Action:     v.action,
		Overridden: v.prev,
		Column:     columnOn(v.node, v.line),
		Certainty:  evidence.Proven,
		Evidence:   evidence.Known,
	}
	if v.certainty != "" {
		f.Certainty = v.certainty
	}
	if v.action == ActionReset {
		f.Value = ""
	}
	if n := deref(v.node); n != nil && n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		f.Null = true
	}
	if redact.MustRedactAt(path, f.Value) {
		f.Secret = true
	}
	for _, c := range f.Overridden {
		if redact.MustRedactAt(path, c.Value) {
			f.Secret = true
		}
	}
	return f
}

func renderVal(v *val) string {
	if v == nil {
		return ""
	}
	if len(v.kids) > 0 {
		parts := make([]string, 0, len(v.order))
		for _, k := range v.order {
			parts = append(parts, k+"="+renderVal(v.kids[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return render(v.node)
}

func render(n *yaml.Node) string {
	n = deref(n)
	if n == nil {
		return ""
	}
	switch n.Kind {
	case yaml.ScalarNode:
		if n.Tag == "!!null" {
			return ""
		}
		return n.Value
	case yaml.SequenceNode:
		parts := make([]string, 0, len(n.Content))
		for _, c := range n.Content {
			parts = append(parts, render(c))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case yaml.MappingNode:
		parts := make([]string, 0, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := deref(n.Content[i])
			key := ""
			if k != nil {
				key = k.Value
			}
			parts = append(parts, key+"="+render(n.Content[i+1]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			return render(n.Content[0])
		}
	}
	return n.Value
}

func customTag(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	t := n.Tag
	if t == TagReset || t == TagOverride {
		return t
	}
	if strings.HasPrefix(t, "!") && !strings.HasPrefix(t, "!!") {
		return t
	}
	return ""
}

func lineOf(n *yaml.Node) int {
	if n == nil {
		return 0
	}
	return n.Line
}

func nullNode() *yaml.Node {
	return &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!null", Value: ""}
}

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

func clone(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	if n.Content != nil {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, ch := range n.Content {
			c.Content[i] = clone(ch)
		}
	}
	return &c
}

func SecretFragments(fields []Field) []string {
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
	for _, f := range fields {
		if !f.Secret {
			continue
		}
		if f.Value != "" {
			if redact.LooksLikeSecret(f.Value) {
				for _, frag := range redact.SecretFragments(f.Value) {
					add(frag)
				}
			} else {
				add(f.Value)
			}
		}
		for _, c := range f.Overridden {
			if c.Value == "" {
				continue
			}
			if redact.LooksLikeSecret(c.Value) {
				for _, frag := range redact.SecretFragments(c.Value) {
					add(frag)
				}
			} else if redact.MustRedactAt(f.Path, c.Value) {
				add(c.Value)
			}
		}
	}
	return out
}

// columnOn returns n's column when n sits on line, else 0.
func columnOn(n *yaml.Node, line int) int {
	n = deref(n)
	if n == nil || line == 0 || n.Line != line {
		return 0
	}
	return n.Column
}

// linkSecretFlags marks the list item after a secret-named flag item as
// secret: in command: ["--token", "VALUE"] the value sits in its own item and
// carries no secret name of its own.
func linkSecretFlags(fields []Field) {
	byPath := make(map[string]int, len(fields))
	for i, f := range fields {
		byPath[f.Path] = i
	}
	for _, f := range fields {
		if !strings.HasSuffix(f.Path, "]") {
			continue
		}
		open := strings.LastIndexByte(f.Path, '[')
		if open < 0 {
			continue
		}
		n, err := strconv.Atoi(f.Path[open+1 : len(f.Path)-1])
		if err != nil {
			continue
		}
		next := f.Path[:open] + "[" + strconv.Itoa(n+1) + "]"
		if j, ok := byPath[next]; ok && redact.SecretFlagValue(f.Value, fields[j].Value) {
			fields[j].Secret = true
		}
	}
}

// cloneOrigins is clone that copies each node's origin from src into dst
// for its copy. dst may be nil when src is empty.
func cloneOrigins(n *yaml.Node, src, dst map[*yaml.Node]string) *yaml.Node {
	if len(src) == 0 {
		return clone(n)
	}
	if n == nil {
		return nil
	}
	c := *n
	if f, ok := src[n]; ok {
		dst[&c] = f
	}
	if n.Content != nil {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, ch := range n.Content {
			c.Content[i] = cloneOrigins(ch, src, dst)
		}
	}
	return &c
}

// applyOrigins sets the file of every value whose node came from another
// file (a base service pulled in by extends), so its provenance names the
// file that holds it rather than the extending file. Sequence items record
// their own file in seqMeta.
func applyOrigins(v *val, origins map[*yaml.Node]string) {
	if v == nil || len(origins) == 0 {
		return
	}
	n := deref(v.node)
	if f, ok := origins[n]; ok {
		v.file = f
	}
	for _, k := range v.order {
		applyOrigins(v.kids[k], origins)
	}
	if n == nil || n.Kind != yaml.SequenceNode || len(v.seqMeta) > 0 {
		return
	}
	differs := false
	for _, c := range n.Content {
		if f, ok := origins[deref(c)]; ok && f != v.file {
			differs = true
			break
		}
	}
	if !differs {
		return
	}
	v.seqMeta = make([]seqMeta, len(n.Content))
	for i, c := range n.Content {
		file := v.file
		if f, ok := origins[deref(c)]; ok {
			file = f
		}
		v.seqMeta[i] = seqMeta{file: file, line: lineOf(c), action: v.action}
	}
}

// withholdEmbeddedSecrets marks a field secret when its value embeds a secret
// value: a secret variable substituted by interpolation ("-p${DB_PASSWORD}"),
// or the value of a field that is already secret, such as a YAML anchor whose
// alias sits under a secret key. The field is withheld instead of the output
// being refused. Interpolated secrets retain sensitivity at every length;
// the output policy separately decides whether a short value can be scanned.
func withholdEmbeddedSecrets(fields []Field, interpolated []string) {
	var secrets []string
	add := func(s string) {
		if len(s) >= safety.MinScanLen {
			secrets = append(secrets, s)
		}
	}
	for _, s := range interpolated {
		if s != "" {
			secrets = append(secrets, s)
		}
	}
	for _, f := range fields {
		if f.Secret {
			add(f.Value)
		}
	}
	if len(secrets) == 0 {
		return
	}
	for i := range fields {
		if fields[i].Secret || fields[i].Value == "" {
			continue
		}
		for _, s := range secrets {
			if strings.Contains(fields[i].Value, s) {
				fields[i].Secret = true
				break
			}
		}
	}
}

// markUnknown sets every value of a document to unknown certainty.
func markUnknown(v *val) {
	if v == nil {
		return
	}
	v.certainty = evidence.Unknown
	for _, k := range v.order {
		markUnknown(v.kids[k])
	}
}
