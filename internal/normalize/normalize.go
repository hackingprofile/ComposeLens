// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"sort"
	"strconv"
	"strings"

	"composelens/internal/evidence"
	"composelens/internal/idpath"
	"composelens/internal/merge"
	"composelens/internal/redact"
)

// Model is the canonical view of dual-form Compose fields on the already-merged
// model. It does not re-run interpolation, merge, profiles, include, extends, or
// container-environment resolution. environment / env_file stay with containerenv.
type Model struct {
	Services []Service
}

type Service struct {
	Name        string
	Ports       []Port
	Volumes     []Volume
	Labels      Labels
	Command     *Command
	Entrypoint  *Command
	Healthcheck *Healthcheck
}

type Provenance struct {
	Source    string
	Line      int
	Secret    bool
	Certainty string
	Evidence  string
	Reason    string
	Raw       string
}

type Port struct {
	HostIP     string
	Published  string
	Target     string
	Protocol   string
	Mode       string
	Provenance Provenance
}

type Volume struct {
	Type        string
	Source      string
	Target      string
	ReadOnly    bool
	SELinux     string
	Propagation string
	Nocopy      bool
	Subpath     string
	TmpfsSize   string
	TmpfsMode   string
	CreateHost  string // "true" / "false" / empty if unset
	// ShortSyntax is set for a "source:target[:mode]" entry. The short bind
	// syntax implies create_host_path: true.
	ShortSyntax bool
	Extra       []string
	Provenance  Provenance
}

type Labels struct {
	Pairs      []Label
	Provenance Provenance
}

type Label struct {
	Key        string
	Value      string
	Provenance Provenance
}

type Command struct {
	Form       string // shell | exec | unknown
	Shell      string
	Argv       []string
	Provenance Provenance
}

type Healthcheck struct {
	Kind       string // CMD | CMD-SHELL | NONE | unknown
	Args       []string
	Provenance Provenance
}

const (
	FormShell = "shell"
	FormExec  = "exec"

	KindCMD      = "CMD"
	KindCMDShell = "CMD-SHELL"
	KindNONE     = "NONE"

	defaultProtocol = "tcp"
	defaultMode     = "ingress"
)

// FromMerge canonicalizes dual-form fields from merge-stage fields. Provenance
// (winning file, line, secret) is copied from those fields, never invented.
func FromMerge(fields []merge.Field) Model {
	names := serviceNames(fields)
	out := Model{Services: make([]Service, 0, len(names))}
	for _, name := range names {
		out.Services = append(out.Services, Service{
			Name:        name,
			Ports:       parsePorts(fields, name),
			Volumes:     parseVolumes(fields, name),
			Labels:      parseLabels(fields, name),
			Command:     parseCommand(fields, name, "command"),
			Entrypoint:  parseCommand(fields, name, "entrypoint"),
			Healthcheck: parseHealthcheck(fields, name),
		})
	}
	return out
}

func Equal(a, b Model) bool {
	if len(a.Services) != len(b.Services) {
		return false
	}
	byName := func(m Model) map[string]Service {
		out := make(map[string]Service, len(m.Services))
		for _, s := range m.Services {
			out[s.Name] = s
		}
		return out
	}
	am, bm := byName(a), byName(b)
	if len(am) != len(bm) {
		return false
	}
	for name, as := range am {
		bs, ok := bm[name]
		if !ok {
			return false
		}
		if !ServiceEqual(as, bs) {
			return false
		}
	}
	return true
}

func ServiceEqual(a, b Service) bool {
	return a.Name == b.Name &&
		PortsEqual(a.Ports, b.Ports) &&
		VolumesEqual(a.Volumes, b.Volumes) &&
		LabelsEqual(a.Labels, b.Labels) &&
		CommandEqual(a.Command, b.Command) &&
		CommandEqual(a.Entrypoint, b.Entrypoint) &&
		HealthcheckEqual(a.Healthcheck, b.Healthcheck)
}

func comparable(p Provenance) bool {
	return p.Certainty != evidence.Unknown && p.Certainty != evidence.Unsupported && p.Evidence != evidence.Unsupported
}

func unknownProv(raw, reason, source string, line int, secret bool) Provenance {
	ev := evidence.Unresolved
	if reason != "" {
		ev = evidence.Unsupported
	}
	return Provenance{
		Source:    source,
		Line:      line,
		Secret:    secret,
		Certainty: evidence.Unknown,
		Evidence:  ev,
		Reason:    reason,
		Raw:       raw,
	}
}

func provenProv(source string, line int, secret bool) Provenance {
	return Provenance{
		Source:    source,
		Line:      line,
		Secret:    secret,
		Certainty: evidence.Proven,
		Evidence:  evidence.Known,
	}
}

func inferredProv(source string, line int, secret bool, reason string) Provenance {
	return Provenance{
		Source:    source,
		Line:      line,
		Secret:    secret,
		Certainty: evidence.Inferred,
		Evidence:  evidence.Known,
		Reason:    reason,
	}
}

func itemOrChildren(fields []merge.Field, ip string) (merge.Field, map[string]string, bool) {
	kids := childMap(fields, ip)
	item, ok := fieldByPath(fields, ip)
	if ok {
		if item.Secret {
			return item, kids, true
		}
		for _, f := range fields {
			if strings.HasPrefix(f.Path, ip+".") && f.Secret {
				item.Secret = true
				break
			}
		}
		return item, kids, true
	}
	if len(kids) == 0 {
		return merge.Field{}, nil, false
	}
	item = merge.Field{Path: ip}
	for _, f := range fields {
		if !strings.HasPrefix(f.Path, ip+".") {
			continue
		}
		if item.Winner == "" {
			item.Winner = f.Winner
			item.Line = f.Line
			item.Action = f.Action
			item.Certainty = f.Certainty
			item.Evidence = f.Evidence
		}
		if f.Secret {
			item.Secret = true
		}
	}
	return item, kids, true
}

func fieldByPath(fields []merge.Field, path string) (merge.Field, bool) {
	for _, f := range fields {
		if f.Path == path {
			return f, true
		}
	}
	return merge.Field{}, false
}

func servicePrefix(name, field string) string {
	return idpath.Join(name, field)
}

func serviceNames(fields []merge.Field) []string {
	return merge.ServiceNames(fields)
}

func sequenceIndices(fields []merge.Field, listPath string) []int {
	seen := map[int]struct{}{}
	prefix := listPath + "["
	for _, f := range fields {
		if !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		rest := strings.TrimPrefix(f.Path, prefix)
		br := strings.IndexByte(rest, ']')
		if br < 0 {
			continue
		}
		n, err := strconv.Atoi(rest[:br])
		if err != nil {
			continue
		}
		seen[n] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for n := range seen {
		out = append(out, n)
	}
	sort.Ints(out)
	return out
}

func itemPath(listPath string, i int) string {
	return listPath + "[" + strconv.Itoa(i) + "]"
}

func childMap(fields []merge.Field, itemPath string) map[string]string {
	prefix := itemPath + "."
	out := map[string]string{}
	for _, f := range fields {
		if !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		key := strings.TrimPrefix(f.Path, prefix)
		out[key] = f.Value
	}
	return out
}

func hasSequenceItems(fields []merge.Field, path string) bool {
	prefix := path + "["
	for _, f := range fields {
		if strings.HasPrefix(f.Path, prefix) {
			return true
		}
	}
	return false
}

func sequenceValues(fields []merge.Field, listPath string) ([]string, merge.Field, bool) {
	idxs := sequenceIndices(fields, listPath)
	if len(idxs) == 0 {
		return nil, merge.Field{}, false
	}
	parent, _ := fieldByPath(fields, listPath)
	vals := make([]string, 0, len(idxs))
	for _, i := range idxs {
		item, ok := fieldByPath(fields, itemPath(listPath, i))
		if !ok {
			continue
		}
		vals = append(vals, item.Value)
		if parent.Path == "" {
			parent = item
		}
		if item.Secret {
			parent.Secret = true
		}
	}
	return vals, parent, true
}

func secretish(key, value string, flagged bool) bool {
	return flagged || redact.MustRedact(key, value) || redact.LooksLikeSecret(value)
}

func parseBool(s string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "true", "yes", "1":
		return true, true
	case "false", "no", "0", "":
		return false, true
	default:
		return false, false
	}
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func ServiceByName(m Model, name string) (Service, bool) {
	for _, s := range m.Services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

// SecretFragments returns secret material that must not appear in public output.
func SecretFragments(m Model) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(key, val string) {
		if val == "" {
			return
		}
		if !redact.MustRedact(key, val) && !redact.LooksLikeSecret(val) {
			return
		}
		if redact.LooksLikeSecret(val) {
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
			return
		}
		if _, ok := seen[val]; ok {
			return
		}
		seen[val] = struct{}{}
		out = append(out, val)
	}
	for _, s := range m.Services {
		for _, p := range s.Ports {
			if p.Provenance.Secret {
				add("", p.Provenance.Raw)
				add("", p.HostIP)
				add("", p.Published)
				add("", p.Target)
			}
		}
		for _, v := range s.Volumes {
			if v.Provenance.Secret {
				add("", v.Provenance.Raw)
				add("", v.Source)
				add("", v.Target)
			}
		}
		for _, l := range s.Labels.Pairs {
			if l.Provenance.Secret {
				add(l.Key, l.Value)
			}
		}
		if s.Command != nil && s.Command.Provenance.Secret {
			add("", s.Command.Shell)
			add("", s.Command.Provenance.Raw)
			for _, a := range s.Command.Argv {
				add("", a)
			}
		}
		if s.Entrypoint != nil && s.Entrypoint.Provenance.Secret {
			add("", s.Entrypoint.Shell)
			add("", s.Entrypoint.Provenance.Raw)
			for _, a := range s.Entrypoint.Argv {
				add("", a)
			}
		}
		if s.Healthcheck != nil && s.Healthcheck.Provenance.Secret {
			add("", s.Healthcheck.Provenance.Raw)
			for _, a := range s.Healthcheck.Args {
				add("", a)
			}
		}
	}
	return out
}
