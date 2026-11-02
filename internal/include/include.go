// SPDX-License-Identifier: Apache-2.0

package include

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/digest"
	"composelens/internal/discover"
	"composelens/internal/evidence"
	"composelens/internal/interp"
	"composelens/internal/paths"
	"composelens/internal/safety"
)

const MaxDepth = 16

const (
	FormShort = "short"
	FormLong  = "long"

	StateOK          = "ok"
	StateCycle       = "cycle"
	StateDepth       = "depth"
	StateAbsent      = "absent"
	StateUnsupported = "unsupported"
	StateError       = "error"
	// NotListReason marks an include: written as a scalar or a mapping instead
	// of a list. Compose rejects such a file; ComposeLens applies the entry as
	// a one-item list, marks it unknown, and check reports it as an error.
	NotListReason = "Compose requires include: to be a list and rejects this file; applied here as a one-item list"

	// MultiDocumentReason marks a loaded file that holds more than one YAML
	// document: only the first is applied, while Compose merges them all.
	MultiDocumentReason = "the file holds several YAML documents; only the first is applied here, while Compose merges them all"
)

type Loader func(canonical string) (*composeparse.Document, error)

type Spec struct {
	Form              string
	Path              string
	ProjectDirectory  string
	EnvFile           string
	UnsupportedFields []string
	// NotList is set when include: is a scalar or a mapping, not a list.
	NotList bool `json:"-"`
}

type Ref struct {
	Spec      Spec
	Resolved  string
	State     string
	Reason    string
	Certainty string
	Evidence  string
	Nested    *Graph
	CycleVia  []string
	docs      []*composeparse.Document
}

type Graph struct {
	File     string
	Refs     []Ref
	HasCycle bool
}

type Result struct {
	Docs   []*composeparse.Document
	Graph  *Graph
	Chains map[string][]string
	Err    error
}

func LoaderWithBudget(b *safety.Budget) Loader {
	return func(canonical string) (*composeparse.Document, error) {
		return loadDisk(b, canonical)
	}
}

func DiskLoad(canonical string) (*composeparse.Document, error) {
	return loadDisk(nil, canonical)
}

func loadDisk(b *safety.Budget, canonical string) (*composeparse.Document, error) {
	chargePath := canonical
	if abs, err := paths.Canonical(canonical); err == nil {
		chargePath = abs
	}
	raw, err := safety.ReadCharged(b, chargePath, safety.MaxFileBytes)
	if err != nil {
		return nil, err
	}
	return composeparse.Parse(discover.File{
		Path:   canonical,
		Bytes:  raw,
		Digest: digest.Bytes(raw),
		Origin: "include",
	})
}

func Expand(doc *composeparse.Document, load Loader, g interp.Getter) Result {
	if load == nil {
		load = DiskLoad
	}
	r := Result{Chains: map[string][]string{}}
	if doc == nil {
		return r
	}
	expansions := 0
	gph, docs, err := expand(doc, load, g, nil, 0, r.Chains, &expansions)
	r.Graph = gph
	r.Docs = docs
	r.Err = err
	return r
}

func expand(doc *composeparse.Document, load Loader, getter interp.Getter, stack []string, depth int, chains map[string][]string, expansions *int) (*Graph, []*composeparse.Document, error) {
	graph := &Graph{File: doc.File.Path}
	canon := doc.File.Path
	chain := append(append([]string{}, stack...), canon)
	if _, ok := chains[canon]; !ok {
		chains[canon] = append([]string{}, chain...)
	}
	if depth > MaxDepth {
		graph.Refs = append(graph.Refs, Ref{
			State:     StateDepth,
			Reason:    "include nesting exceeds bounded depth",
			Certainty: evidence.Proven,
			Evidence:  evidence.Unsupported,
		})
		return graph, []*composeparse.Document{withoutInclude(doc)}, nil
	}
	var specs []Spec
	if getter != nil {
		probe := cloneYAML(doc.Root)
		interp.InterpolateTree(probe, getter)
		specs = parseIncludes(probe)
	} else {
		specs = parseIncludes(doc.Root)
	}
	var docs []*composeparse.Document
	for _, spec := range specs {
		ref, err := resolveOne(doc.File.Path, spec, load, getter, stack, depth, chains, expansions)
		if err != nil {
			return graph, docs, err
		}
		if ref.State == StateCycle || (ref.Nested != nil && ref.Nested.HasCycle) {
			graph.HasCycle = true
		}
		graph.Refs = append(graph.Refs, ref)
		docs = append(docs, ref.docs...)
	}
	docs = append(docs, withoutInclude(doc))
	return graph, docs, nil
}

func resolveOne(including string, spec Spec, load Loader, g interp.Getter, stack []string, depth int, chains map[string][]string, expansions *int) (Ref, error) {
	ref, err := resolveSpec(including, spec, load, g, stack, depth, chains, expansions)
	if spec.NotList {
		// Applied as a one-item list so the model stays useful, but Compose
		// rejects the file: never proven, and check reports it.
		ref.Certainty = evidence.Unknown
		if ref.Reason != "" {
			ref.Reason = NotListReason + "; " + ref.Reason
		} else {
			ref.Reason = NotListReason
		}
		for _, d := range ref.docs {
			if d != nil {
				d.Uncertain = NotListReason
			}
		}
	}
	return ref, err
}

func resolveSpec(including string, spec Spec, load Loader, g interp.Getter, stack []string, depth int, chains map[string][]string, expansions *int) (Ref, error) {
	ref := Ref{
		Spec:      spec,
		Certainty: evidence.Proven,
		Evidence:  evidence.Known,
		State:     StateOK,
	}
	if spec.Path == "" {
		ref.State = StateUnsupported
		ref.Evidence = evidence.Unsupported
		ref.Certainty = evidence.Unknown
		ref.Reason = "include entry has no path"
		return ref, nil
	}
	if IsRemote(spec.Path) {
		ref.State = StateUnsupported
		ref.Evidence = evidence.Unsupported
		ref.Certainty = evidence.Unknown
		ref.Reason = "remote include is not loaded; the engine would resolve it over the network"
		return ref, nil
	}
	base := filepath.Dir(including)
	resolved, err := paths.Resolve(base, spec.Path)
	if err != nil {
		ref.State = StateError
		ref.Reason = err.Error()
		return ref, nil
	}
	ref.Resolved = resolved
	if len(spec.UnsupportedFields) > 0 {
		ref.Certainty = evidence.Unknown
		ref.Reason = "long-form " + strings.Join(spec.UnsupportedFields, ", ") + " not applied (unknown vs official engine)"
	}
	newStack := append(append([]string{}, stack...), including)
	for _, p := range newStack {
		if samePath(p, resolved) {
			ref.State = StateCycle
			ref.Evidence = evidence.Known
			ref.Certainty = evidence.Proven
			ref.Reason = "include cycle"
			ref.CycleVia = append(append([]string{}, newStack...), resolved)
			return ref, nil
		}
	}
	// Every expansion counts, repeated references included: caching loads
	// would not bound the serialized graph of a repeated-include DAG.
	*expansions++
	if *expansions > safety.MaxIncludeExpansions {
		return ref, safety.NewParseError(safety.CodeIncludeExpansion, "", fmt.Sprintf("include expansion exceeds %d files per root file", safety.MaxIncludeExpansions))
	}
	child, err := load(resolved)
	if err != nil {
		if safety.IsRefusal(err) {
			return ref, err
		}
		if os.IsNotExist(err) {
			ref.State = StateAbsent
			ref.Evidence = evidence.Absent
			ref.Reason = "included file not found"
			return ref, nil
		}
		ref.State = StateError
		ref.Reason = err.Error()
		return ref, nil
	}
	if child.File.Path == "" {
		child.File.Path = resolved
	}
	if len(child.More) > 0 {
		ref.Certainty = evidence.Unknown
		if ref.Reason != "" {
			ref.Reason += "; "
		}
		ref.Reason += MultiDocumentReason
	}
	nested, nestedDocs, err := expand(child, load, g, newStack, depth+1, chains, expansions)
	if err != nil {
		return ref, err
	}
	ref.Nested = nested
	ref.docs = nestedDocs
	return ref, nil
}

func parseIncludes(root *yaml.Node) []Spec {
	n := mappingRoot(root)
	if n == nil {
		return nil
	}
	var node *yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k != nil && k.Value == "include" {
			node = deref(n.Content[i+1])
			break
		}
	}
	if node == nil || node.Tag == "!!null" {
		return nil
	}
	switch node.Kind {
	case yaml.ScalarNode:
		s := shortSpec(node.Value)
		s.NotList = true
		return []Spec{s}
	case yaml.SequenceNode:
		var out []Spec
		for _, c := range node.Content {
			out = append(out, specFrom(deref(c)))
		}
		return out
	case yaml.MappingNode:
		s := specFrom(node)
		s.NotList = true
		return []Spec{s}
	default:
		return []Spec{{Form: FormLong, UnsupportedFields: []string{"include"}}}
	}
}

func specFrom(n *yaml.Node) Spec {
	if n == nil {
		return Spec{Form: FormShort}
	}
	if n.Kind == yaml.ScalarNode {
		return shortSpec(n.Value)
	}
	if n.Kind != yaml.MappingNode {
		return Spec{Form: FormLong, UnsupportedFields: []string{"include"}}
	}
	s := Spec{Form: FormLong}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := deref(n.Content[i]), deref(n.Content[i+1])
		if k == nil {
			continue
		}
		val := ""
		if v != nil {
			val = v.Value
		}
		switch k.Value {
		case "path":
			s.Path = val
		case "project_directory":
			s.ProjectDirectory = val
			s.UnsupportedFields = append(s.UnsupportedFields, "project_directory")
		case "env_file":
			s.EnvFile = val
			s.UnsupportedFields = append(s.UnsupportedFields, "env_file")
		default:
			s.UnsupportedFields = append(s.UnsupportedFields, k.Value)
		}
	}
	return s
}

func shortSpec(path string) Spec {
	return Spec{Form: FormShort, Path: path}
}

func withoutInclude(doc *composeparse.Document) *composeparse.Document {
	if doc == nil || doc.Root == nil {
		return doc
	}
	out := *doc
	out.Root = cloneYAML(doc.Root)
	stripInclude(out.Root)
	return &out
}

func stripInclude(n *yaml.Node) {
	n = deref(n)
	if n == nil {
		return
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		stripInclude(n.Content[0])
		return
	}
	if n.Kind != yaml.MappingNode {
		return
	}
	var content []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k != nil && k.Value == "include" {
			continue
		}
		content = append(content, n.Content[i], n.Content[i+1])
	}
	n.Content = content
}

func cloneYAML(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	c := *n
	if n.Content != nil {
		c.Content = make([]*yaml.Node, len(n.Content))
		for i, ch := range n.Content {
			c.Content[i] = cloneYAML(ch)
		}
	}
	return &c
}

func mappingRoot(n *yaml.Node) *yaml.Node {
	n = deref(n)
	if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = deref(n.Content[0])
	}
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	return n
}

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
}

func samePath(a, b string) bool {
	return filepath.Clean(a) == filepath.Clean(b)
}

// IsRemote reports whether an include path names a remote resource (OCI,
// Git or HTTP reference) that the engine would resolve over the network.
func IsRemote(path string) bool {
	p := strings.TrimSpace(path)
	if strings.HasPrefix(p, "git@") || schemelessGit(p) {
		return true
	}
	i := strings.Index(p, "://")
	if i <= 1 {
		return false
	}
	for _, r := range p[:i] {
		if !schemeRune(r) {
			return false
		}
	}
	return true
}

// schemeRune reports a character allowed in a URL scheme (RFC 3986).
func schemeRune(r rune) bool {
	return r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '+' || r == '.' || r == '-'
}

// schemelessGit reports a Git address written without a scheme, such as
// "github.com/docker/awesome-compose.git#master:nginx-golang": a first
// element that is a host name (it holds a dot and is not "." or ".."), and a
// later element ending in ".git", optionally followed by "#ref". The engine
// would clone it, so it is remote; a local path never starts with a host.
func schemelessGit(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\`) || strings.HasPrefix(p, ".") {
		return false
	}
	if len(p) >= 2 && p[1] == ':' {
		return false // a Windows drive
	}
	host, rest, ok := strings.Cut(p, "/")
	if !ok || !strings.Contains(host, ".") || strings.ContainsAny(host, `\:@`) {
		return false
	}
	if i := strings.IndexByte(rest, '#'); i >= 0 {
		rest = rest[:i]
	}
	for _, seg := range strings.Split(rest, "/") {
		if strings.HasSuffix(seg, ".git") && len(seg) > len(".git") {
			return true
		}
	}
	return false
}
