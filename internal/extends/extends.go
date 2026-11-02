// SPDX-License-Identifier: Apache-2.0

package extends

import (
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
	"composelens/internal/redact"
	"composelens/internal/safety"
	"composelens/internal/shortvol"
)

const MaxDepth = 16

const (
	FormMapping = "mapping"
	FormShort   = "short"

	StateOK          = "ok"
	StateCycle       = "cycle"
	StateDepth       = "depth"
	StateAbsent      = "absent"
	StateUnsupported = "unsupported"
	StateError       = "error"

	OriginInherited = "inherited"
	OriginOverride  = "override"
	OriginAdd       = "add"
	OriginConcat    = "concat"
)

// Relationship keys the Compose Specification excludes from extends inheritance.
var excludedKeys = map[string]struct{}{
	"depends_on":     {},
	"links":          {},
	"volumes_from":   {},
	"container_name": {},
	"ipc":            {},
	"pid":            {},
	"network_mode":   {},
	"net":            {},
	"extends":        {},
}

var sequenceKeys = map[string]struct{}{
	"cap_add": {}, "cap_drop": {}, "configs": {}, "device_cgroup_rules": {},
	"expose": {}, "external_links": {}, "ports": {}, "secrets": {}, "security_opt": {},
}

var volumeKeys = map[string]struct{}{
	"volumes": {}, "devices": {},
}

type Loader func(canonical string) (*composeparse.Document, error)

type Spec struct {
	Form              string
	Service           string
	File              string
	UnsupportedFields []string
}

type Ref struct {
	Name        string
	Form        string
	Service     string
	File        string
	Resolved    string
	State       string
	Reason      string
	Certainty   string
	Evidence    string
	Excluded    []string
	CycleVia    []string
	Nested      *Ref
	BaseFile    string
	BaseService string
}

type Graph struct {
	File     string
	Refs     []Ref
	HasCycle bool
}

type Field struct {
	Path        string
	Origin      string
	Value       string
	File        string
	Service     string
	BaseFile    string
	BaseService string
	Chain       []string
	Sources     []string
	Secret      bool
	Certainty   string
	Evidence    string
}

type Result struct {
	Doc    *composeparse.Document
	Graph  *Graph
	Fields []Field
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
		Origin: "extends",
	})
}

func Apply(doc *composeparse.Document, load Loader, g interp.Getter) Result {
	if load == nil {
		load = DiskLoad
	}
	r := Result{Doc: doc}
	if doc == nil || doc.Root == nil {
		return r
	}
	out := *doc
	out.Root = cloneYAML(doc.Root)
	secretVals := interp.InterpolateTreeSecrets(out.Root, g)
	if g != nil {
		out.Interpolated = true
	}
	frozen := cloneYAML(out.Root)
	ctx := &resolveCtx{
		load:     load,
		getter:   g,
		files:    map[string]*yaml.Node{doc.File.Path: frozen},
		resolved: map[string]svcResult{},
		origins:  map[*yaml.Node]string{},
		multiDoc: map[string]bool{},
	}
	gph := &Graph{File: doc.File.Path}
	var fields []Field
	svcs := servicesMap(out.Root)
	if svcs != nil {
		frozenSvcs := servicesMap(frozen)
		for _, name := range mappingKeysIn(svcs) {
			res := ctx.resolve(doc.File.Path, name, mappingValue(frozenSvcs, name), 0, nil)
			if ctx.boundErr != nil {
				r.Err = ctx.boundErr
				return r
			}
			if res.ref.State == StateCycle || nestedCycle(res.ref.Nested) {
				gph.HasCycle = true
			}
			if res.ref.Form != "" || res.ref.State != "" {
				gph.Refs = append(gph.Refs, res.ref)
			}
			setMappingValue(svcs, name, res.node)
			annotated := annotate(doc.File.Path, name, res)
			for i := range annotated {
				annotated[i].Sources = ctx.fieldSources(name, annotated[i].Path, res.chain)
			}
			fields = append(fields, annotated...)
		}
	}
	if len(ctx.origins) > 0 {
		out.Origins = ctx.origins
	}
	secretVals = append(secretVals, ctx.secretVals...)
	out.SecretValues = secretVals
	r.Doc = &out
	r.Graph = gph
	r.Fields = fields
	r.Err = ctx.boundErr
	return r
}

// fieldSources lists only files whose original service defines this field.
func (c *resolveCtx) fieldSources(service, field string, chain []string) []string {
	rest := strings.TrimPrefix(field, "services."+service)
	var out []string
	for _, hop := range chain {
		i := strings.LastIndex(hop, "::")
		if i < 0 {
			continue
		}
		file, svc := hop[:i], hop[i+2:]
		node := mappingValue(servicesMap(c.files[file]), svc)
		if _, exists := flatten(node, "services."+service)["services."+service+rest]; exists {
			out = append(out, file)
		}
	}
	return out
}

type resolveCtx struct {
	// origins maps every node loaded from another file, and each clone of it,
	// to that file.
	origins map[*yaml.Node]string
	// secretVals are secret variable values substituted into loaded files.
	secretVals []string
	// multiDoc marks loaded files that hold several YAML documents.
	multiDoc map[string]bool
	load     Loader
	getter   interp.Getter
	files    map[string]*yaml.Node
	resolved map[string]svcResult
	boundErr error
}

type svcResult struct {
	node        *yaml.Node
	ref         Ref
	baseNode    *yaml.Node
	childNode   *yaml.Node
	baseFile    string
	baseService string
	chain       []string
}

func (c *resolveCtx) resolve(file, name string, node *yaml.Node, depth int, stack []string) svcResult {
	id := file + "::" + name
	if cached, ok := c.resolved[id]; ok {
		return cached
	}
	node = deref(node)
	res := svcResult{node: node, chain: []string{id}}
	if node == nil || node.Kind != yaml.MappingNode {
		return res
	}
	spec, ok := parseExtends(node)
	if !ok {
		res.ref.Name = name
		res.childNode = node
		return res
	}
	ref := Ref{
		Name:      name,
		Form:      spec.Form,
		Service:   spec.Service,
		File:      spec.File,
		Certainty: evidence.Proven,
		Evidence:  evidence.Known,
		State:     StateOK,
	}
	local := c.stripExtends(node)
	fail := func(state, evid, reason string) svcResult {
		ref.State = state
		if evid != "" {
			ref.Evidence = evid
		}
		if reason != "" {
			ref.Reason = reason
		}
		return svcResult{node: local, ref: ref, childNode: local, chain: res.chain}
	}
	if spec.Form == FormShort {
		ref.Certainty = evidence.Unknown
		return fail(StateUnsupported, evidence.Unsupported, "Compose Specification requires mapping form {service, file?}; string short form is not applied")
	}
	if spec.Service == "" {
		ref.Certainty = evidence.Unknown
		return fail(StateUnsupported, evidence.Unsupported, "extends mapping has no service")
	}
	if len(spec.UnsupportedFields) > 0 {
		ref.Certainty = evidence.Unknown
		ref.Reason = "unsupported extends fields " + strings.Join(spec.UnsupportedFields, ", ")
	}
	if depth > MaxDepth {
		return fail(StateDepth, evidence.Unsupported, "extends nesting exceeds bounded depth")
	}
	baseFile := file
	if spec.File != "" {
		resolved, err := paths.Resolve(filepath.Dir(file), spec.File)
		if err != nil {
			return fail(StateError, evidence.Known, err.Error())
		}
		baseFile = resolved
	}
	ref.Resolved = baseFile
	ref.BaseFile = baseFile
	ref.BaseService = spec.Service
	newStack := append(append([]string{}, stack...), id)
	baseID := baseFile + "::" + spec.Service
	for _, p := range newStack {
		if p == baseID {
			ref.CycleVia = append(append([]string{}, newStack...), baseID)
			return fail(StateCycle, evidence.Known, "extends cycle")
		}
	}
	root, err := c.fileRoot(baseFile)
	if err != nil {
		if os.IsNotExist(err) {
			return fail(StateAbsent, evidence.Absent, "extends file not found")
		}
		return fail(StateError, evidence.Known, err.Error())
	}
	baseRaw := mappingValue(servicesMap(root), spec.Service)
	if baseRaw == nil {
		return fail(StateAbsent, evidence.Absent, "extends target service not found")
	}
	if c.multiDoc[baseFile] {
		ref.Certainty = evidence.Unknown
		if ref.Reason != "" {
			ref.Reason += "; "
		}
		ref.Reason += "the extended file holds several YAML documents; only the first is applied here, while Compose merges them all"
	}
	baseRes := c.resolve(baseFile, spec.Service, baseRaw, depth+1, newStack)
	if baseRes.ref.Form != "" || baseRes.ref.State == StateCycle {
		n := baseRes.ref
		ref.Nested = &n
	}
	if baseRes.ref.State == StateCycle || nestedCycle(baseRes.ref.Nested) {
		ref.State = StateCycle
		ref.Reason = "extends cycle"
		ref.CycleVia = baseRes.ref.CycleVia
		if len(ref.CycleVia) == 0 {
			ref.CycleVia = append(append([]string{}, newStack...), baseID)
		}
	}
	filtered, skipped := c.omitExcluded(baseRes.node)
	ref.Excluded = skipped
	merged := c.overlayService(filtered, local)
	chain := []string{id}
	if baseRes.ref.State != StateCycle && !nestedCycle(baseRes.ref.Nested) {
		chain = append(chain, baseRes.chain...)
	} else {
		chain = append(chain, baseID)
	}
	out := svcResult{
		node:        merged,
		ref:         ref,
		baseNode:    filtered,
		childNode:   local,
		baseFile:    baseFile,
		baseService: spec.Service,
		chain:       chain,
	}
	c.resolved[id] = out
	return out
}

func (c *resolveCtx) fileRoot(canonical string) (*yaml.Node, error) {
	if n, ok := c.files[canonical]; ok {
		return n, nil
	}
	doc, err := c.load(canonical)
	if err != nil {
		if safety.IsRefusal(err) {
			c.boundErr = err
		}
		return nil, err
	}
	if len(doc.More) > 0 {
		c.multiDoc[canonical] = true
	}
	root := cloneYAML(doc.Root)
	c.secretVals = append(c.secretVals, interp.InterpolateTreeSecrets(root, c.getter)...)
	c.markOrigin(root, canonical)
	c.files[canonical] = root
	return root, nil
}

func parseExtends(svc *yaml.Node) (Spec, bool) {
	n := mappingValue(svc, "extends")
	if n == nil || n.Tag == "!!null" {
		return Spec{}, false
	}
	n = deref(n)
	if n.Kind == yaml.ScalarNode {
		return Spec{Form: FormShort, Service: n.Value}, true
	}
	if n.Kind != yaml.MappingNode {
		return Spec{Form: FormMapping, UnsupportedFields: []string{"extends"}}, true
	}
	s := Spec{Form: FormMapping}
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
		case "service":
			s.Service = val
		case "file":
			s.File = val
		default:
			s.UnsupportedFields = append(s.UnsupportedFields, k.Value)
		}
	}
	return s, true
}

func (c *resolveCtx) omitExcluded(n *yaml.Node) (*yaml.Node, []string) {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return n, nil
	}
	out := c.clone(n)
	var skipped []string
	var content []*yaml.Node
	for i := 0; i+1 < len(out.Content); i += 2 {
		k := deref(out.Content[i])
		if k != nil {
			if _, bad := excludedKeys[k.Value]; bad {
				skipped = append(skipped, k.Value)
				continue
			}
		}
		content = append(content, out.Content[i], out.Content[i+1])
	}
	out.Content = content
	return out, skipped
}

func (c *resolveCtx) stripExtends(n *yaml.Node) *yaml.Node {
	n = c.clone(deref(n))
	if n == nil || n.Kind != yaml.MappingNode {
		return n
	}
	var content []*yaml.Node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k != nil && k.Value == "extends" {
			continue
		}
		content = append(content, n.Content[i], n.Content[i+1])
	}
	n.Content = content
	return n
}

func (c *resolveCtx) overlayService(base, child *yaml.Node) *yaml.Node {
	base, child = deref(base), deref(child)
	if child == nil {
		return c.clone(base)
	}
	if base == nil || base.Kind != yaml.MappingNode || child.Kind != yaml.MappingNode {
		return c.clone(child)
	}
	out := c.clone(base)
	for i := 0; i+1 < len(child.Content); i += 2 {
		k := deref(child.Content[i])
		if k == nil {
			continue
		}
		merged := c.mergeKey(k.Value, mappingValue(out, k.Value), child.Content[i+1])
		setMappingValue(out, k.Value, merged)
	}
	return out
}

func (c *resolveCtx) mergeKey(key string, base, child *yaml.Node) *yaml.Node {
	base, child = deref(base), deref(child)
	if child == nil {
		return c.clone(base)
	}
	if base == nil {
		return c.clone(child)
	}
	if _, vol := volumeKeys[key]; vol && base.Kind == yaml.SequenceNode && child.Kind == yaml.SequenceNode {
		return c.mergeByTarget(base, child)
	}
	if _, seq := sequenceKeys[key]; seq && base.Kind == yaml.SequenceNode && child.Kind == yaml.SequenceNode {
		return c.concatUnique(base, child)
	}
	if base.Kind == yaml.MappingNode && child.Kind == yaml.MappingNode {
		return c.overlayService(base, child)
	}
	return c.clone(child)
}

func (c *resolveCtx) concatUnique(base, child *yaml.Node) *yaml.Node {
	out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	seen := map[string]struct{}{}
	add := func(n *yaml.Node) {
		n = c.clone(deref(n))
		sig := render(n)
		if _, ok := seen[sig]; ok {
			return
		}
		seen[sig] = struct{}{}
		out.Content = append(out.Content, n)
	}
	for _, it := range base.Content {
		add(it)
	}
	for _, it := range child.Content {
		add(it)
	}
	return out
}

func (c *resolveCtx) mergeByTarget(base, child *yaml.Node) *yaml.Node {
	type item struct {
		node   *yaml.Node
		target string
	}
	var order []item
	idx := map[string]int{}
	add := func(n *yaml.Node) {
		n = c.clone(deref(n))
		t := volumeTarget(n)
		if t == "" {
			t = render(n)
		}
		if i, ok := idx[t]; ok {
			order[i].node = n
			return
		}
		idx[t] = len(order)
		order = append(order, item{node: n, target: t})
	}
	for _, it := range base.Content {
		add(it)
	}
	for _, it := range child.Content {
		add(it)
	}
	out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	for _, it := range order {
		out.Content = append(out.Content, it.node)
	}
	return out
}

func volumeTarget(n *yaml.Node) string {
	n = deref(n)
	if n == nil {
		return ""
	}
	if n.Kind == yaml.MappingNode {
		if v := mappingValue(n, "target"); v != nil {
			return v.Value
		}
		return ""
	}
	if n.Kind != yaml.ScalarNode {
		return ""
	}
	return shortvol.Target(n.Value)
}

func annotate(file, svc string, res svcResult) []Field {
	if res.childNode == nil && res.baseNode == nil {
		return nil
	}
	prefix := "services." + svc
	chain := res.chain
	if len(chain) == 0 {
		chain = []string{file + "::" + svc}
	}
	var out []Field
	seen := map[string]struct{}{}
	add := func(path, origin, value string) {
		if origin == "" {
			return
		}
		if _, ok := seen[path]; ok {
			return
		}
		seen[path] = struct{}{}
		f := Field{
			Path:        path,
			Origin:      origin,
			Value:       value,
			File:        file,
			Service:     svc,
			BaseFile:    res.baseFile,
			BaseService: res.baseService,
			Chain:       append([]string{}, chain...),
			Certainty:   evidence.Proven,
			Evidence:    evidence.Known,
		}
		if redact.MustRedactAt(path, value) || redact.LooksLikeSecret(value) {
			f.Secret = true
		}
		out = append(out, f)
	}
	resultLeaves := flatten(res.node, prefix)
	childLeaves := flatten(res.childNode, prefix)
	baseLeaves := flatten(res.baseNode, prefix)
	for path, val := range resultLeaves {
		_, inC := childLeaves[path]
		_, inB := baseLeaves[path]
		switch {
		case inC && inB:
			add(path, OriginOverride, val)
		case inC:
			add(path, OriginAdd, val)
		case inB:
			add(path, OriginInherited, val)
		}
	}
	for _, key := range []string{"ports", "expose", "cap_add", "cap_drop", "configs", "secrets", "volumes", "devices"} {
		p := prefix + "." + key
		cb := mappingValue(res.baseNode, key)
		cc := mappingValue(res.childNode, key)
		if cb != nil && cc != nil && deref(cb).Kind == yaml.SequenceNode && deref(cc).Kind == yaml.SequenceNode {
			add(p, OriginConcat, render(mappingValue(res.node, key)))
		}
	}
	return out
}

func flatten(n *yaml.Node, path string) map[string]string {
	out := map[string]string{}
	n = deref(n)
	if n == nil {
		return out
	}
	switch n.Kind {
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := deref(n.Content[i])
			if k == nil {
				continue
			}
			child := k.Value
			if path != "" {
				child = path + "." + k.Value
			}
			for p, v := range flatten(n.Content[i+1], child) {
				out[p] = v
			}
		}
	case yaml.SequenceNode:
		out[path] = render(n)
		for i, c := range n.Content {
			idx := path + "[" + itoa(i) + "]"
			for p, v := range flatten(c, idx) {
				out[p] = v
			}
		}
	default:
		out[path] = render(n)
	}
	return out
}

func nestedCycle(r *Ref) bool {
	for r != nil {
		if r.State == StateCycle {
			return true
		}
		r = r.Nested
	}
	return false
}

func SecretFragments(fields []Field) []string {
	seen := map[string]struct{}{}
	var out []string
	for _, f := range fields {
		if !f.Secret || f.Value == "" {
			continue
		}
		frags := []string{f.Value}
		if redact.LooksLikeSecret(f.Value) {
			frags = redact.SecretFragments(f.Value)
		}
		for _, s := range frags {
			if s == "" {
				continue
			}
			if _, ok := seen[s]; ok {
				continue
			}
			seen[s] = struct{}{}
			out = append(out, s)
		}
	}
	return out
}

func servicesMap(root *yaml.Node) *yaml.Node {
	m := mappingRoot(root)
	if m == nil {
		return nil
	}
	return mappingValue(m, "services")
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

func mappingValue(n *yaml.Node, key string) *yaml.Node {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k != nil && k.Value == key {
			return deref(n.Content[i+1])
		}
	}
	return nil
}

func mappingKeysIn(n *yaml.Node) []string {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	var out []string
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k != nil {
			out = append(out, k.Value)
		}
	}
	return out
}

func setMappingValue(n *yaml.Node, key string, val *yaml.Node) {
	n = deref(n)
	if n == nil || n.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k := deref(n.Content[i])
		if k != nil && k.Value == key {
			n.Content[i+1] = val
			return
		}
	}
	n.Content = append(n.Content, &yaml.Node{Kind: yaml.ScalarNode, Tag: "!!str", Value: key}, val)
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

func deref(n *yaml.Node) *yaml.Node {
	if n != nil && n.Kind == yaml.AliasNode && n.Alias != nil {
		return n.Alias
	}
	return n
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

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}

// markOrigin records file as the origin of every node under root, including
// alias targets.
func (c *resolveCtx) markOrigin(root *yaml.Node, file string) {
	seen := map[*yaml.Node]bool{}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil || seen[n] {
			return
		}
		seen[n] = true
		c.origins[n] = file
		walk(n.Alias)
		for _, ch := range n.Content {
			walk(ch)
		}
	}
	walk(root)
}

// clone is cloneYAML that keeps each node's recorded origin on its copy.
func (c *resolveCtx) clone(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	cp := *n
	if f, ok := c.origins[n]; ok {
		c.origins[&cp] = f
	}
	if n.Content != nil {
		cp.Content = make([]*yaml.Node, len(n.Content))
		for i, ch := range n.Content {
			cp.Content[i] = c.clone(ch)
		}
	}
	return &cp
}
