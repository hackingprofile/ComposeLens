// SPDX-License-Identifier: Apache-2.0

package composeparse

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"

	"composelens/internal/discover"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

type Location struct {
	File   string `json:"file"`
	Line   int    `json:"line"`
	Column int    `json:"column"`
}

type Service struct {
	Name     string   `json:"name"`
	Location Location `json:"location"`
}

type Document struct {
	File     discover.File
	Root     *yaml.Node
	Services []Service
	// Interpolated is true after interpolation has already written resolved
	// scalars into Root (extends does this). Merge must not InterpolateTree
	// again: a second pass would treat escaped `$VAR` as a real variable.
	Interpolated bool
	// Origins names the file each node came from when it is not File: extends
	// copies a base service from another file into this document, and its
	// values keep that file for provenance. Nil when every node is from File.
	Origins map[*yaml.Node]string
	// SecretValues are values of secret variables substituted into Root before
	// merge (extends interpolates a document itself). Merge withholds any field
	// that embeds one.
	SecretValues []string
	// More holds the further YAML documents of the same file, in order. Compose
	// merges them over the first as further files; callers that load a file
	// as a whole must apply them too.
	More []*Document
	// Uncertain, when set, says why no value of this document is proven (for
	// example it arrived through an include: form Compose rejects).
	Uncertain string
}

type Limits struct {
	MaxFileBytes      int
	MaxYAMLDepth      int
	MaxAliasExpansion int
	MaxYAMLNodes      int
	Timeout           time.Duration
}

func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:      safety.MaxFileBytes,
		MaxYAMLDepth:      safety.MaxYAMLDepth,
		MaxAliasExpansion: safety.MaxAliasExpansion,
		MaxYAMLNodes:      safety.MaxYAMLNodes,
		Timeout:           safety.DefaultParseTimeout,
	}
}

func Parse(file discover.File) (*Document, error) {
	return ParseWithLimits(file, DefaultLimits())
}

func ParseWithLimits(file discover.File, lim Limits) (*Document, error) {
	lim = fillLimits(lim)
	if err := checkSize(file, lim); err != nil {
		return nil, err
	}
	if len(file.Bytes) == 0 {
		return nil, safety.NewParseError(safety.CodeMalformed, file.Path, "empty input")
	}
	if !utf8.Valid(file.Bytes) {
		return nil, safety.NewParseError(safety.CodeEncoding, file.Path, "input is not valid UTF-8")
	}

	type result struct {
		doc *Document
		err error
	}
	ch := make(chan result, 1)
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				ch <- result{err: safety.NewParseError(safety.CodeMalformed, file.Path, "parser refused hostile input")}
			}
		}()
		doc, err := parseInner(file, lim)
		ch <- result{doc: doc, err: err}
	}()
	timer := time.NewTimer(lim.Timeout)
	defer timer.Stop()
	select {
	case r := <-ch:
		return r.doc, r.err
	case <-timer.C:
		return nil, safety.NewParseError(safety.CodeTimeout, file.Path, "parse exceeded time bound")
	}
}

func fillLimits(lim Limits) Limits {
	d := DefaultLimits()
	if lim.MaxFileBytes <= 0 {
		lim.MaxFileBytes = d.MaxFileBytes
	}
	if lim.MaxYAMLDepth <= 0 {
		lim.MaxYAMLDepth = d.MaxYAMLDepth
	}
	if lim.MaxAliasExpansion <= 0 {
		lim.MaxAliasExpansion = d.MaxAliasExpansion
	}
	if lim.MaxYAMLNodes <= 0 {
		lim.MaxYAMLNodes = d.MaxYAMLNodes
	}
	if lim.Timeout <= 0 {
		lim.Timeout = d.Timeout
	}
	return lim
}

func checkSize(file discover.File, lim Limits) error {
	n := len(file.Bytes)
	if n > lim.MaxFileBytes {
		return safety.NewParseError(safety.CodeFileTooLarge, file.Path, fmt.Sprintf("file exceeds %d bytes", lim.MaxFileBytes))
	}
	return nil
}

func parseInner(file discover.File, lim Limits) (*Document, error) {
	dec := yaml.NewDecoder(bytes.NewReader(file.Bytes))
	var root yaml.Node
	if err := dec.Decode(&root); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, safety.NewParseError(safety.CodeMalformed, file.Path, "empty input")
		}
		return nil, mapYAMLError(file.Path, err)
	}
	if err := enforceBounds(&root, lim); err != nil {
		var pe *safety.ParseError
		if errors.As(err, &pe) && pe.Path == "" {
			pe.Path = file.Path
		}
		return nil, err
	}
	if err := checkTopLevel(&root, file.Path); err != nil {
		return nil, err
	}
	doc := &Document{File: file, Root: &root}
	doc.Services = servicesFromRoot(file.Path, &root)
	// Compose merges every YAML document of a file in order, later documents
	// overriding earlier ones, as if each were a further -f file.
	for {
		var next yaml.Node
		err := dec.Decode(&next)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, mapYAMLError(file.Path, err)
		}
		if emptyDocument(&next) {
			continue
		}
		if err := enforceBounds(&next, lim); err != nil {
			var pe *safety.ParseError
			if errors.As(err, &pe) && pe.Path == "" {
				pe.Path = file.Path
			}
			return nil, err
		}
		if err := checkTopLevel(&next, file.Path); err != nil {
			return nil, err
		}
		more := &Document{File: file, Root: &next}
		more.Services = servicesFromRoot(file.Path, &next)
		doc.More = append(doc.More, more)
	}
	return doc, nil
}

// emptyDocument reports a document with no content or only a null, such as
// a trailing "---".
func emptyDocument(n *yaml.Node) bool {
	if n.Kind == yaml.DocumentNode && len(n.Content) == 0 {
		return true
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) == 1 {
		c := n.Content[0]
		return c.Kind == yaml.ScalarNode && c.Tag == "!!null"
	}
	return false
}

func mapYAMLError(path string, err error) error {
	msg := err.Error()
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "excessive aliasing"):
		return safety.NewParseError(safety.CodeAliasLimit, path, "anchor/alias expansion exceeds bound")
	case strings.Contains(low, "max depth"):
		return safety.NewParseError(safety.CodeTooDeep, path, fmt.Sprintf("YAML nesting exceeds %d", safety.MaxYAMLDepth))
	default:
		return safety.NewParseError(safety.CodeMalformed, path, "malformed YAML")
	}
}

func checkTopLevel(root *yaml.Node, path string) error {
	n := root
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	n = deref(n)
	if n == nil || n.Kind == yaml.ScalarNode && (n.Tag == "!!null" || n.Value == "" || n.Value == "null") {
		return safety.NewParseError(safety.CodeNotMapping, path, "top-level YAML value is not a mapping")
	}
	if n.Kind != yaml.MappingNode {
		return safety.NewParseError(safety.CodeNotMapping, path, "top-level YAML value is not a mapping")
	}
	return nil
}

type boundState struct {
	lim     Limits
	nodes   int
	alias   int
	inStack map[*yaml.Node]bool
}

func enforceBounds(root *yaml.Node, lim Limits) error {
	st := &boundState{lim: lim, inStack: map[*yaml.Node]bool{}}
	return walkBounds(root, 0, st)
}

func walkBounds(n *yaml.Node, depth int, st *boundState) error {
	if n == nil {
		return nil
	}
	st.nodes++
	if st.nodes > st.lim.MaxYAMLNodes {
		return safety.NewParseError(safety.CodeTooManyNodes, "", fmt.Sprintf("YAML node count exceeds %d", st.lim.MaxYAMLNodes))
	}
	if n.Kind == yaml.AliasNode {
		st.alias++
		if st.alias > st.lim.MaxAliasExpansion {
			return safety.NewParseError(safety.CodeAliasLimit, "", "anchor/alias expansion exceeds bound")
		}
		if n.Alias == nil {
			return nil
		}
		if st.inStack[n.Alias] {
			return safety.NewParseError(safety.CodeAliasLimit, "", "alias cycle")
		}
		return walkBounds(n.Alias, depth, st)
	}
	if n.Kind == yaml.MappingNode || n.Kind == yaml.SequenceNode {
		if n.Kind != yaml.DocumentNode {
			depth++
			if depth > st.lim.MaxYAMLDepth {
				return safety.NewParseError(safety.CodeTooDeep, "", fmt.Sprintf("YAML nesting exceeds %d", st.lim.MaxYAMLDepth))
			}
		}
		if st.inStack[n] {
			return safety.NewParseError(safety.CodeAliasLimit, "", "alias cycle")
		}
		st.inStack[n] = true
		defer delete(st.inStack, n)
		if n.Kind == yaml.MappingNode {
			if err := duplicateKeys(n); err != nil {
				return err
			}
		}
	}
	for _, c := range n.Content {
		if err := walkBounds(c, depth, st); err != nil {
			return err
		}
	}
	return nil
}

func duplicateKeys(n *yaml.Node) error {
	seen := map[string]struct{}{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k == nil {
			continue
		}
		key := k.Value
		if key == "" {
			continue
		}
		if _, ok := seen[key]; ok {
			return safety.NewParseError(safety.CodeDuplicateKey, "", "duplicate mapping key")
		}
		seen[key] = struct{}{}
	}
	return nil
}

func SafeErrorMessage(err error) string {
	if err == nil {
		return ""
	}
	msg := err.Error()
	if redact.LooksLikeSecret(msg) {
		if c := safety.CodeOf(err); c != "" {
			return fmt.Sprintf("parse: diagnostic redacted (%s)", c)
		}
		return "parse: diagnostic redacted"
	}
	return msg
}

// Scalar is a string YAML value with a dotted path and source location.
type Scalar struct {
	Path     string
	Location Location
	Value    string
}

// StringScalars walks mapping values and sequence items. Mapping keys are not
// interpolated (Compose interpolates values). Non-string tags are skipped.
func StringScalars(doc *Document) []Scalar {
	if doc == nil || doc.Root == nil {
		return nil
	}
	var out []Scalar
	walkScalars(doc.File.Path, doc.Root, "", map[*yaml.Node]bool{}, &out)
	return out
}

func walkScalars(file string, n *yaml.Node, path string, inStack map[*yaml.Node]bool, out *[]Scalar) {
	n = deref(n)
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) > 0 {
			walkScalars(file, n.Content[0], path, inStack, out)
		}
	case yaml.MappingNode:
		if inStack[n] {
			return
		}
		inStack[n] = true
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := deref(n.Content[i]), n.Content[i+1]
			key := ""
			if k != nil {
				key = k.Value
			}
			child := key
			if path != "" && key != "" {
				child = path + "." + key
			} else if path != "" {
				child = path
			}
			walkScalars(file, v, child, inStack, out)
		}
		delete(inStack, n)
	case yaml.SequenceNode:
		if inStack[n] {
			return
		}
		inStack[n] = true
		for i, c := range n.Content {
			child := path + "[" + strconv.Itoa(i) + "]"
			if path == "" {
				child = "[" + strconv.Itoa(i) + "]"
			}
			walkScalars(file, c, child, inStack, out)
		}
		delete(inStack, n)
	case yaml.ScalarNode:
		if !isStringScalar(n) {
			return
		}
		*out = append(*out, Scalar{
			Path: path,
			Location: Location{
				File:   file,
				Line:   n.Line,
				Column: n.Column,
			},
			Value: n.Value,
		})
	}
}

func isStringScalar(n *yaml.Node) bool {
	switch n.Tag {
	case "!!bool", "!!int", "!!float", "!!null", "!!binary", "!!timestamp", "!!merge":
		return false
	default:
		return n.Kind == yaml.ScalarNode
	}
}

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

func servicesFromRoot(file string, root *yaml.Node) []Service {
	n := root
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value != "services" {
			continue
		}
		v = deref(v)
		if v == nil || v.Kind != yaml.MappingNode {
			return nil
		}
		var out []Service
		for j := 0; j+1 < len(v.Content); j += 2 {
			sk := v.Content[j]
			name := sk.Value
			if sk.Kind == yaml.AliasNode && sk.Alias != nil {
				name = sk.Alias.Value
			}
			out = append(out, Service{
				Name: name,
				Location: Location{
					File:   file,
					Line:   sk.Line,
					Column: sk.Column,
				},
			})
		}
		return out
	}
	return nil
}
