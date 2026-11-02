// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"composelens/internal/evidence"
	"composelens/internal/idpath"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/paths"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

const (
	KindEnvFile     = "env-file"
	KindEnvironment = "environment"
	KindHostShell   = "host-shell"

	FormMap         = "map"
	FormList        = "list"
	FormPassThrough = "pass-through"

	StateSet    = "set"
	StateUnset  = "unset"
	StateAbsent = "absent"
)

// Documented Compose Specification order for the container environment
// (lowest to highest among in-scope sources):
//  1. env_file (list order; later file overrides earlier)
//  2. environment (overrides env_file even when empty or undefined)
//
// List/map pass-through (`- KEY` / `KEY:`) takes the host-shell value.
// If the host does not have KEY, the variable is removed.
// Dockerfile ENV and `docker compose run -e` are out of scope.

type Contributor struct {
	Kind   string
	Path   string
	Line   int
	Form   string
	Value  string
	Unset  bool
	Reason string
}

type Variable struct {
	Service    string
	Key        string
	Value      string
	State      string
	Winner     Contributor
	Overridden []Contributor
	Secret     bool
	Certainty  string
	Evidence   string
	Reason     string
}

type FileRef struct {
	Path     string
	Resolved string
	State    string
	// Outside is set when the file resolves outside the project directory.
	// It is read, as Compose reads it, but every value from it is withheld.
	Outside   bool
	Required  bool
	Format    string
	Reason    string
	Certainty string
	Evidence  string
}

type ServiceEnv struct {
	Service string
	Files   []FileRef
	Vars    []Variable
}

func Resolve(fields []merge.Field, host map[string]string, g interp.Getter, budget ...*safety.Budget) ([]ServiceEnv, error) {
	return ResolveConfined("", fields, host, g, budget...)
}

// OutsideReason explains why an env_file's values are withheld.
const OutsideReason = "env_file is outside the project directory; its values are withheld"

// ResolveConfined is Resolve with the project directory as the confinement
// root: a service env_file that resolves outside root (absolute, "..", or a
// symlink) is read, but all of its values are withheld from output. An empty
// root confines nothing.
func ResolveConfined(root string, fields []merge.Field, host map[string]string, g interp.Getter, budget ...*safety.Budget) ([]ServiceEnv, error) {
	b := safety.Optional(budget)
	if host == nil {
		host = map[string]string{}
	}
	byPath := map[string]merge.Field{}
	for _, f := range fields {
		byPath[f.Path] = f
	}
	names := serviceNames(fields)
	out := make([]ServiceEnv, 0, len(names))
	for _, name := range names {
		se, err := resolveService(root, name, byPath, host, g, b)
		if err != nil {
			return nil, err
		}
		out = append(out, se)
	}
	return out, nil
}

func resolveService(root, name string, byPath map[string]merge.Field, host map[string]string, g interp.Getter, b *safety.Budget) (ServiceEnv, error) {
	se := ServiceEnv{Service: name}
	type slot struct {
		val  string
		set  bool
		win  Contributor
		lost []Contributor
		cert string
		ev   string
		sec  bool
		why  string
	}
	slots := map[string]*slot{}
	order := make([]string, 0)
	touch := func(key string) *slot {
		if s, ok := slots[key]; ok {
			return s
		}
		s := &slot{cert: evidence.Proven, ev: evidence.Known}
		slots[key] = s
		order = append(order, key)
		return s
	}
	apply := func(key string, c Contributor, set bool, val string) {
		s := touch(key)
		if s.set || s.win.Kind != "" {
			prev := s.win
			prev.Value = s.val
			prev.Unset = !s.set
			s.lost = append(s.lost, prev)
		}
		s.win = c
		s.set = set
		s.val = val
		if c.Reason != "" {
			s.why = c.Reason
			if strings.Contains(c.Reason, "unknown") {
				s.cert = evidence.Unknown
			}
		}
		if redact.MustRedact(key, val) {
			s.sec = true
		}
	}

	se.Files = envFiles(byPath, name)
	for i := range se.Files {
		fr := &se.Files[i]
		if fr.State != "ok" {
			continue
		}
		if root != "" && !paths.Within(root, fr.Resolved) {
			fr.Outside = true
			if fr.Reason != "" {
				fr.Reason += "; "
			}
			fr.Reason += OutsideReason
		}
		entries, err := readEnvFile(fr.Resolved, fr.Format, g, b)
		if err != nil {
			if safety.IsRefusal(err) {
				return se, err
			}
			fr.State = "error"
			fr.Reason = err.Error()
			fr.Evidence = evidence.Known
			continue
		}
		for _, e := range entries {
			c := Contributor{Kind: KindEnvFile, Path: fr.Resolved, Line: e.Line, Form: KindEnvFile, Value: e.Value, Unset: e.Unset}
			if e.Unset {
				apply(e.Key, c, false, "")
				continue
			}
			apply(e.Key, c, true, e.Value)
			if fr.Outside {
				slots[e.Key].sec = true
			}
		}
	}

	for _, item := range environmentItems(byPath, name) {
		c := Contributor{Kind: KindEnvironment, Form: item.Form, Line: item.Line, Path: item.File}
		if item.PassThrough {
			c.Kind = KindHostShell
			c.Form = FormPassThrough
			c.Reason = "environment pass-through from host shell"
			if v, ok := host[item.Key]; ok {
				c.Value = v
				apply(item.Key, c, true, v)
			} else {
				c.Unset = true
				apply(item.Key, c, false, "")
			}
			continue
		}
		c.Value = item.Value
		apply(item.Key, c, true, item.Value)
		if item.Secret {
			slots[item.Key].sec = true
		}
	}

	vars := make([]Variable, 0, len(order))
	for _, key := range order {
		s := slots[key]
		st := StateSet
		if !s.set {
			st = StateUnset
		}
		v := Variable{
			Service:    name,
			Key:        key,
			Value:      s.val,
			State:      st,
			Winner:     s.win,
			Overridden: s.lost,
			Secret:     s.sec || redact.MustRedact(key, s.val),
			Certainty:  s.cert,
			Evidence:   s.ev,
			Reason:     s.why,
		}
		if v.Secret {
			v.Secret = true
		}
		for _, o := range v.Overridden {
			if redact.MustRedact(key, o.Value) {
				v.Secret = true
			}
		}
		if !v.Secret {
			v.Secret = redact.MustRedact(key, v.Value)
		}
		vars = append(vars, v)
	}
	sort.Slice(vars, func(i, j int) bool { return vars[i].Key < vars[j].Key })
	se.Vars = vars
	return se, nil
}

type envItem struct {
	Secret      bool
	Key         string
	Value       string
	PassThrough bool
	Form        string
	File        string
	Line        int
}

func environmentItems(byPath map[string]merge.Field, svc string) []envItem {
	p := "services." + svc + ".environment"
	if f, ok := byPath[p]; ok && f.Action == merge.ActionReset {
		return nil
	}
	var out []envItem
	idxs := indexed(byPath, p)
	if len(idxs) > 0 {
		for _, it := range idxs {
			key, val, pass, ok := splitListEnv(it.value)
			if !ok {
				continue
			}
			out = append(out, envItem{Key: key, Value: val, PassThrough: pass, Form: FormList, File: it.file, Line: it.line, Secret: it.secret})
		}
		return out
	}
	prefix := p + "."
	type pair struct {
		key string
		f   merge.Field
	}
	var ps []pair
	for path, f := range byPath {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := path[len(prefix):]
		if strings.ContainsAny(rest, ".[") {
			continue
		}
		ps = append(ps, pair{key: rest, f: f})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].key < ps[j].key })
	for _, it := range ps {
		item := envItem{Key: it.key, Value: it.f.Value, Form: FormMap, File: it.f.Winner, Line: it.f.Line, Secret: it.f.Secret}
		// `KEY:` (null) passes the host value through; `KEY: ""` sets an empty
		// string, as Compose distinguishes them.
		if it.f.Value == "" && it.f.Null {
			item.PassThrough = true
		}
		out = append(out, item)
	}
	return out
}

func splitListEnv(s string) (key, val string, pass bool, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false, false
	}
	i := strings.IndexByte(s, '=')
	if i < 0 {
		if !envNameOK(s) {
			return "", "", false, false
		}
		return s, "", true, true
	}
	key = strings.TrimSpace(s[:i])
	if !envNameOK(key) {
		return "", "", false, false
	}
	return key, s[i+1:], false, true
}

func envNameOK(s string) bool {
	return idpath.EnvOK(s)
}

type fileSpec struct {
	path     string
	required bool
	format   string
	file     string
	line     int
	unknown  []string
}

func envFiles(byPath map[string]merge.Field, svc string) []FileRef {
	p := "services." + svc + ".env_file"
	if f, ok := byPath[p]; ok && f.Action == merge.ActionReset {
		return nil
	}
	var specs []fileSpec
	idxs := indexed(byPath, p)
	if len(idxs) == 0 {
		if f, ok := byPath[p]; ok && f.Value != "" && !strings.HasPrefix(f.Value, "[") && !strings.HasPrefix(f.Value, "{") {
			specs = append(specs, fileSpec{path: f.Value, required: true, file: f.Winner, line: f.Line})
		}
	}
	// One ordered list: short entries (env_file[N]) and long-form mappings
	// (env_file[N].path …) keep their list index, so a mixed list loads every
	// entry in order, as the engine does.
	type long struct {
		i int
		s fileSpec
	}
	var longs []long
	for _, it := range idxs {
		if strings.HasPrefix(it.value, "{") || it.value == "" {
			continue
		}
		longs = append(longs, long{i: it.i, s: fileSpec{path: it.value, required: true, file: it.file, line: it.line}})
	}
	for path, f := range byPath {
		if !strings.HasPrefix(path, p+"[") {
			continue
		}
		rest := path[len(p)+1:]
		end := strings.IndexByte(rest, ']')
		if end <= 0 {
			continue
		}
		idx, err := strconv.Atoi(rest[:end])
		if err != nil {
			continue
		}
		tail := ""
		if len(rest) > end+1 && rest[end+1] == '.' {
			tail = rest[end+2:]
		}
		if tail == "" {
			continue
		}
		var spec *fileSpec
		for i := range longs {
			if longs[i].i == idx {
				spec = &longs[i].s
				break
			}
		}
		if spec == nil {
			longs = append(longs, long{i: idx, s: fileSpec{required: true, file: f.Winner, line: f.Line}})
			spec = &longs[len(longs)-1].s
		}
		switch tail {
		case "path":
			spec.path = f.Value
			spec.file = f.Winner
			spec.line = f.Line
		case "required":
			spec.required = f.Value != "false" && f.Value != "False"
		case "format":
			spec.format = f.Value
		default:
			spec.unknown = append(spec.unknown, tail)
		}
	}
	sort.SliceStable(longs, func(i, j int) bool { return longs[i].i < longs[j].i })
	if len(longs) > 0 {
		specs = nil
		for _, l := range longs {
			specs = append(specs, l.s)
		}
	}
	out := make([]FileRef, 0, len(specs))
	for _, s := range specs {
		fr := FileRef{
			Path:      s.path,
			Required:  s.required,
			Format:    s.format,
			Certainty: evidence.Proven,
			Evidence:  evidence.Known,
			State:     "ok",
		}
		if len(s.unknown) > 0 {
			fr.Certainty = evidence.Unknown
			fr.Evidence = evidence.Unsupported
			fr.Reason = "unsupported env_file fields " + strings.Join(s.unknown, ", ")
		}
		if s.format != "" && s.format != "raw" {
			fr.Certainty = evidence.Unknown
			fr.Evidence = evidence.Unsupported
			if fr.Reason != "" {
				fr.Reason += "; "
			}
			fr.Reason += "env_file format " + s.format + " is unknown; parsed as Compose env_file rules"
		}
		if s.path == "" {
			fr.State = "unsupported"
			fr.Evidence = evidence.Unsupported
			fr.Certainty = evidence.Unknown
			fr.Reason = "env_file entry has no path"
			out = append(out, fr)
			continue
		}
		base := filepath.Dir(s.file)
		resolved, err := paths.Resolve(base, s.path)
		if err != nil {
			fr.State = "error"
			fr.Reason = err.Error()
			out = append(out, fr)
			continue
		}
		fr.Resolved = resolved
		if _, err := os.Stat(resolved); err != nil {
			if os.IsNotExist(err) {
				fr.State = StateAbsent
				fr.Evidence = evidence.Absent
				fr.Reason = "env_file not found"
				if !s.required {
					fr.Reason = "optional env_file not found (ignored)"
				}
			} else {
				fr.State = "error"
				fr.Reason = err.Error()
			}
			out = append(out, fr)
			continue
		}
		out = append(out, fr)
	}
	return out
}

type idxVal struct {
	secret bool
	i      int
	value  string
	file   string
	line   int
}

func indexed(byPath map[string]merge.Field, prefix string) []idxVal {
	var ps []idxVal
	for path, f := range byPath {
		if !strings.HasPrefix(path, prefix+"[") {
			continue
		}
		rest := path[len(prefix)+1:]
		end := strings.IndexByte(rest, ']')
		if end <= 0 {
			continue
		}
		if len(rest) > end+1 {
			continue
		}
		i, err := strconv.Atoi(rest[:end])
		if err != nil {
			continue
		}
		ps = append(ps, idxVal{i: i, value: f.Value, file: f.Winner, line: f.Line, secret: f.Secret})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].i < ps[j].i })
	return ps
}

func serviceNames(fields []merge.Field) []string {
	return merge.ServiceNames(fields)
}

func SecretFragments(svcs []ServiceEnv) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(key, val string) {
		if val == "" {
			return
		}
		if redact.MustRedact(key, val) {
			for _, frag := range redact.SecretFragments(val) {
				if frag == "" {
					continue
				}
				if _, ok := seen[frag]; ok {
					continue
				}
				seen[frag] = struct{}{}
				out = append(out, frag)
			}
			if redact.MustRedact(key, val) && !redact.LooksLikeSecret(val) {
				if _, ok := seen[val]; !ok {
					seen[val] = struct{}{}
					out = append(out, val)
				}
			}
		}
	}
	for _, se := range svcs {
		for _, v := range se.Vars {
			add(v.Key, v.Value)
			add(v.Key, v.Winner.Value)
			for _, o := range v.Overridden {
				add(v.Key, o.Value)
			}
		}
	}
	return out
}
