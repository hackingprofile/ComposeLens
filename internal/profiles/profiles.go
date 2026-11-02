// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"sort"
	"strconv"
	"strings"

	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/merge"
	"composelens/internal/redact"
)

const (
	SourceFlag = "flag"
	SourceEnv  = "COMPOSE_PROFILES"

	StateEnabled     = "enabled"
	StateDisabled    = "disabled"
	StateUnsupported = "unsupported"

	ReasonAlwaysOn = "no-profiles (always on)"
)

func dependsOnInactiveReason(svc string, listed []string) string {
	return "required by " + svc + " via depends_on but gated behind inactive profile {" + strings.Join(listed, ", ") + "}; Docker Compose does not document auto-enabling this — verify against your engine"
}

type ActiveProfile struct {
	Name      string
	Source    string
	Secret    bool
	Evidence  string
	Certainty string
}

type Service struct {
	Name          string
	State         string
	Reason        string
	Listed        []string
	Matched       string
	MatchedSource string
	ImplicitOf    string
	Certainty     string
	Evidence      string
}

// Active builds the active profile set. Repeatable --profile flags win when
// present; otherwise COMPOSE_PROFILES is split on commas. Command-line flags
// outrank COMPOSE_* environment variables (no union). Empty names after trim
// are dropped. First occurrence wins.
// AllProfiles is the profile name that activates every profile
// (--profile '*' or COMPOSE_PROFILES=*), as Compose defines it.
const AllProfiles = "*"

func Active(flagProfiles []string, environ []string) []ActiveProfile {
	var flags []string
	for _, p := range flagProfiles {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		flags = append(flags, p)
	}
	if len(flags) > 0 {
		return uniqued(flags, SourceFlag)
	}
	host := envsrc.HostMap(environ)
	raw, ok := host["COMPOSE_PROFILES"]
	if !ok || strings.TrimSpace(raw) == "" {
		return nil
	}
	var names []string
	for _, p := range strings.Split(raw, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		names = append(names, p)
	}
	return uniqued(names, SourceEnv)
}

func uniqued(names []string, source string) []ActiveProfile {
	seen := map[string]struct{}{}
	out := make([]ActiveProfile, 0, len(names))
	for _, n := range names {
		if _, ok := seen[n]; ok {
			continue
		}
		seen[n] = struct{}{}
		out = append(out, ActiveProfile{
			Name:      n,
			Source:    source,
			Secret:    redact.LooksLikeSecret(n) || redact.MustRedact("COMPOSE_PROFILES", n),
			Evidence:  evidence.Known,
			Certainty: evidence.Proven,
		})
	}
	return out
}

func Activate(fields []merge.Field, active []ActiveProfile) []Service {
	byPath := map[string]merge.Field{}
	for _, f := range fields {
		byPath[f.Path] = f
	}
	src := map[string]string{}
	activeSet := map[string]struct{}{}
	for _, a := range active {
		activeSet[a.Name] = struct{}{}
		src[a.Name] = a.Source
	}
	names := serviceNames(fields)
	type pending struct {
		listed     []string
		unknown    bool
		enabled    bool
		reason     string
		matched    string
		msrc       string
		implicitOf string
		cert       string
		ev         string
		state      string
	}
	info := map[string]*pending{}
	for _, name := range names {
		listed, hasKey, unknown := listedProfiles(byPath, name)
		p := &pending{listed: listed, unknown: unknown, cert: evidence.Proven, ev: evidence.Known, state: StateDisabled}
		if unknown {
			p.state = StateUnsupported
			p.reason = "profiles mapping form unknown/unsupported"
			p.cert = evidence.Unknown
			p.ev = evidence.Unsupported
			info[name] = p
			continue
		}
		if !hasKey {
			p.enabled = true
			p.state = StateEnabled
			p.reason = ReasonAlwaysOn
			info[name] = p
			continue
		}
		for _, pr := range listed {
			if _, ok := activeSet[pr]; ok {
				p.enabled = true
				p.state = StateEnabled
				p.matched = pr
				p.msrc = src[pr]
				p.reason = "enabled by profile " + pr + " (source: " + p.msrc + ")"
				break
			}
		}
		// Compose treats the profile name "*" as every profile.
		if _, all := activeSet[AllProfiles]; all && !p.enabled && len(listed) > 0 {
			p.enabled = true
			p.state = StateEnabled
			p.matched = AllProfiles
			p.msrc = src[AllProfiles]
			p.reason = "enabled by profile * (every profile; source: " + p.msrc + ")"
		}
		if !p.enabled {
			p.reason = "disabled — none of its profiles {" + strings.Join(listed, ", ") + "} are active"
		}
		info[name] = p
	}
	deps := map[string][]string{}
	for _, name := range names {
		deps[name] = dependsOn(byPath, name)
	}
	for _, name := range names {
		p := info[name]
		if p == nil || !p.enabled {
			continue
		}
		for _, dep := range deps[name] {
			d := info[dep]
			if d == nil || d.unknown || d.enabled {
				continue
			}
			if len(d.listed) == 0 {
				continue
			}
			d.implicitOf = name
			d.reason = dependsOnInactiveReason(name, d.listed)
			d.cert = evidence.Unknown
			d.ev = evidence.Unsupported
			d.state = StateDisabled
			d.enabled = false
		}
	}
	out := make([]Service, 0, len(names))
	for _, name := range names {
		p := info[name]
		out = append(out, Service{
			Name:          name,
			State:         p.state,
			Reason:        p.reason,
			Listed:        p.listed,
			Matched:       p.matched,
			MatchedSource: p.msrc,
			ImplicitOf:    p.implicitOf,
			Certainty:     p.cert,
			Evidence:      p.ev,
		})
	}
	return out
}

func SecretFragments(active []ActiveProfile, svcs []Service) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if s == "" || !redact.LooksLikeSecret(s) {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, a := range active {
		if a.Secret {
			add(a.Name)
		}
	}
	for _, s := range svcs {
		add(s.Matched)
		for _, p := range s.Listed {
			add(p)
		}
	}
	return out
}

func serviceNames(fields []merge.Field) []string {
	return merge.ServiceNames(fields)
}

func listedProfiles(byPath map[string]merge.Field, svc string) (listed []string, hasKey bool, unknown bool) {
	p := "services." + svc + ".profiles"
	if f, ok := byPath[p]; ok {
		if f.Action == merge.ActionReset {
			return nil, false, false
		}
		hasKey = true
		if strings.HasPrefix(f.Value, "{") {
			return nil, true, true
		}
	}
	for path := range byPath {
		if path == p {
			continue
		}
		if strings.HasPrefix(path, p+".") && !strings.Contains(path[len(p)+1:], "[") {
			return nil, true, true
		}
	}
	idxs := indexValues(byPath, p)
	if len(idxs) > 0 {
		return idxs, true, false
	}
	if f, ok := byPath[p]; ok {
		if f.Value == "" || f.Value == "[]" {
			return nil, true, false
		}
		if !strings.HasPrefix(f.Value, "[") && !strings.HasPrefix(f.Value, "{") {
			return []string{f.Value}, true, false
		}
		return nil, true, false
	}
	return nil, hasKey, false
}

func dependsOn(byPath map[string]merge.Field, svc string) []string {
	p := "services." + svc + ".depends_on"
	if f, ok := byPath[p]; ok && f.Action == merge.ActionReset {
		return nil
	}
	var names []string
	seen := map[string]struct{}{}
	add := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" {
			return
		}
		if _, ok := seen[n]; ok {
			return
		}
		seen[n] = struct{}{}
		names = append(names, n)
	}
	for _, v := range indexValues(byPath, p) {
		add(v)
	}
	prefix := p + "."
	for path := range byPath {
		if !strings.HasPrefix(path, prefix) {
			continue
		}
		rest := path[len(prefix):]
		if i := strings.IndexByte(rest, '.'); i >= 0 {
			rest = rest[:i]
		}
		if i := strings.IndexByte(rest, '['); i >= 0 {
			continue
		}
		add(rest)
	}
	if len(names) == 0 {
		if f, ok := byPath[p]; ok && f.Value != "" && !strings.HasPrefix(f.Value, "[") && !strings.HasPrefix(f.Value, "{") {
			add(f.Value)
		}
	}
	return names
}

func indexValues(byPath map[string]merge.Field, prefix string) []string {
	type pair struct {
		i int
		v string
	}
	var ps []pair
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
		ps = append(ps, pair{i: i, v: f.Value})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].i < ps[j].i })
	out := make([]string, 0, len(ps))
	for _, p := range ps {
		out = append(out, p.v)
	}
	return out
}
