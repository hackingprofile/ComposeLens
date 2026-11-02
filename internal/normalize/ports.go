// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"

	"composelens/internal/merge"
)

var portLongKeys = map[string]struct{}{
	"target":    {},
	"published": {},
	"host_ip":   {},
	"protocol":  {},
	"mode":      {},
}

func parsePorts(fields []merge.Field, svc string) []Port {
	listPath := servicePrefix(svc, "ports")
	idxs := sequenceIndices(fields, listPath)
	if len(idxs) == 0 {
		return nil
	}
	out := make([]Port, 0, len(idxs))
	for _, i := range idxs {
		ip := itemPath(listPath, i)
		item, kids, ok := itemOrChildren(fields, ip)
		if !ok {
			continue
		}
		if isLongPort(item.Value, kids) {
			out = append(out, parsePortLong(item, kids))
			continue
		}
		out = append(out, parsePortShort(item))
	}
	return out
}

func isLongPort(value string, kids map[string]string) bool {
	if len(kids) == 0 {
		return strings.HasPrefix(strings.TrimSpace(value), "{")
	}
	for k := range kids {
		base, _, _ := strings.Cut(k, ".")
		if _, ok := portLongKeys[base]; ok {
			return true
		}
	}
	return strings.HasPrefix(strings.TrimSpace(value), "{")
}

func parsePortLong(item merge.Field, kids map[string]string) Port {
	secret := secretish("", item.Value, item.Secret)
	var extra []string
	for _, k := range sortedKeys(kids) {
		base, _, _ := strings.Cut(k, ".")
		if _, ok := portLongKeys[base]; ok {
			continue
		}
		extra = append(extra, k)
	}
	if len(extra) > 0 {
		p := Port{Provenance: unknownProv(item.Value, "ports long-form extra keys are not a documented lossless conversion: "+strings.Join(extra, ","), item.Winner, item.Line, secret)}
		fillPortFromKids(&p, kids)
		return p
	}
	p := Port{Provenance: provenProv(item.Winner, item.Line, secret)}
	fillPortFromKids(&p, kids)
	if p.Target == "" {
		p.Provenance = unknownProv(item.Value, "ports long form missing target", item.Winner, item.Line, secret)
	}
	normalizePortDefaults(&p)
	return p
}

func fillPortFromKids(p *Port, kids map[string]string) {
	p.Target = strings.TrimSpace(kids["target"])
	p.Published = strings.TrimSpace(kids["published"])
	p.HostIP = strings.TrimSpace(kids["host_ip"])
	p.Protocol = strings.ToLower(strings.TrimSpace(kids["protocol"]))
	p.Mode = strings.ToLower(strings.TrimSpace(kids["mode"]))
}

func parsePortShort(item merge.Field) Port {
	raw := strings.TrimSpace(item.Value)
	secret := secretish("", raw, item.Secret)
	p, ok := decodePortShort(raw)
	if !ok {
		return Port{Provenance: unknownProv(raw, "ports short syntax could not be parsed without guessing", item.Winner, item.Line, secret)}
	}
	p.Provenance = provenProv(item.Winner, item.Line, secret)
	p.Provenance.Raw = raw
	normalizePortDefaults(&p)
	return p
}

func decodePortShort(raw string) (Port, bool) {
	s := strings.TrimSpace(raw)
	if s == "" || strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[") {
		return Port{}, false
	}
	protocol := ""
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		proto := strings.ToLower(s[i+1:])
		if proto == "tcp" || proto == "udp" || proto == "sctp" {
			protocol = proto
			s = s[:i]
		}
	}
	hostIP, published, target, ok := splitPortHost(s)
	if !ok {
		return Port{}, false
	}
	return Port{
		HostIP:    hostIP,
		Published: published,
		Target:    target,
		Protocol:  protocol,
	}, true
}

func splitPortHost(s string) (hostIP, published, target string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", "", false
		}
		hostIP = s[1:end]
		rest := s[end+1:]
		if rest == "" {
			return "", "", "", false
		}
		if rest[0] != ':' {
			return "", "", "", false
		}
		rest = rest[1:]
		parts := strings.Split(rest, ":")
		switch len(parts) {
		case 1:
			return hostIP, "", parts[0], parts[0] != ""
		case 2:
			return hostIP, parts[0], parts[1], parts[1] != ""
		default:
			return "", "", "", false
		}
	}
	parts := strings.Split(s, ":")
	for _, p := range parts {
		if p == "" {
			return "", "", "", false
		}
	}
	switch len(parts) {
	case 1:
		return "", "", parts[0], true
	case 2:
		return "", parts[0], parts[1], true
	case 3:
		return parts[0], parts[1], parts[2], true
	default:
		return "", "", "", false
	}
}

func normalizePortDefaults(p *Port) {
	if p.Protocol == "" {
		p.Protocol = defaultProtocol
	}
	if p.Mode == "" {
		p.Mode = defaultMode
	}
}

func PortsEqual(a, b []Port) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !PortEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func PortEqual(a, b Port) bool {
	if !comparable(a.Provenance) || !comparable(b.Provenance) {
		return unknownEqual(a.Provenance, b.Provenance)
	}
	return a.HostIP == b.HostIP &&
		a.Published == b.Published &&
		a.Target == b.Target &&
		portProtocol(a) == portProtocol(b) &&
		portMode(a) == portMode(b)
}

func portProtocol(p Port) string {
	if p.Protocol == "" {
		return defaultProtocol
	}
	return strings.ToLower(p.Protocol)
}

func portMode(p Port) string {
	if p.Mode == "" {
		return defaultMode
	}
	return strings.ToLower(p.Mode)
}

func unknownEqual(a, b Provenance) bool {
	if a.Raw == "" || b.Raw == "" {
		return false
	}
	return a.Raw == b.Raw && a.Reason == b.Reason
}

func DisplayPort(p Port) string {
	if !comparable(p.Provenance) && p.Provenance.Raw != "" {
		return "unknown:" + p.Provenance.Raw
	}
	var b strings.Builder
	if p.HostIP != "" {
		b.WriteString("host_ip=")
		b.WriteString(p.HostIP)
		b.WriteByte(' ')
	}
	if p.Published != "" {
		b.WriteString("published=")
		b.WriteString(p.Published)
		b.WriteByte(' ')
	}
	b.WriteString("target=")
	b.WriteString(p.Target)
	b.WriteString(" protocol=")
	b.WriteString(portProtocol(p))
	b.WriteString(" mode=")
	b.WriteString(portMode(p))
	return b.String()
}

func DisplayPorts(ports []Port) string {
	parts := make([]string, 0, len(ports))
	for _, p := range ports {
		parts = append(parts, DisplayPort(p))
	}
	return strings.Join(parts, "; ")
}
