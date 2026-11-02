// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"strings"

	"gopkg.in/yaml.v3"

	"composelens/internal/evidence"
	"composelens/internal/shortvol"
)

// Sequence overlay: command/entrypoint replace as a unit; ports/volumes/secrets/configs
// append with unique-key dedup (later file wins on the same key); other sequences append.

type seqClass int

const (
	seqAtomic seqClass = iota
	seqUnique
	seqAppendVerified
	seqAppendUnverified
)

func overlaySequences(base, over *val, key, path string) *val {
	kind := classifySequence(key, path)
	switch kind {
	case seqAtomic:
		over.action = ActionReplace
		over.prev = lost(base)
		over.certainty = evidence.Proven
		return over
	case seqUnique:
		return mergeUniqueSeq(base, over, key)
	case seqAppendVerified:
		return appendSeq(base, over, evidence.Proven)
	default:
		return appendSeq(base, over, evidence.Unknown)
	}
}

func classifySequence(key, path string) seqClass {
	if key == "command" || key == "entrypoint" {
		return seqAtomic
	}
	if key == "test" && strings.Contains(path, "healthcheck") {
		return seqAtomic
	}
	switch key {
	case "ports", "volumes", "secrets", "configs", "environment", "depends_on":
		return seqUnique
	case "dns", "dns_search", "expose", "cap_add", "cap_drop", "tmpfs", "extra_hosts", "security_opt":
		return seqAppendVerified
	default:
		return seqAppendUnverified
	}
}

func appendSeq(base, over *val, cert string) *val {
	bn := deref(base.node)
	on := deref(over.node)
	out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	var meta []seqMeta
	take := func(src *val, n *yaml.Node, fromOverlay bool) {
		if n == nil {
			return
		}
		for i, c := range n.Content {
			out.Content = append(out.Content, clone(c))
			m := itemMeta(src, i, c)
			if fromOverlay {
				m.action = ActionAdd
			}
			meta = append(meta, m)
		}
	}
	take(base, bn, false)
	take(over, on, true)
	return &val{
		node:      out,
		file:      over.file,
		line:      over.line,
		action:    ActionAppend,
		seqMeta:   meta,
		certainty: cert,
	}
}

func mergeUniqueSeq(base, over *val, key string) *val {
	bn := deref(base.node)
	on := deref(over.node)
	out := &yaml.Node{Kind: yaml.SequenceNode, Tag: "!!seq"}
	var meta []seqMeta
	index := map[string]int{}
	keyed := true
	add := func(src *val, n *yaml.Node, fromOverlay bool) {
		if n == nil {
			return
		}
		for i, c := range n.Content {
			item := wrap(c, src.file, ActionSource)
			if i < len(src.seqMeta) {
				item.file = src.seqMeta[i].file
				item.line = src.seqMeta[i].line
				item.action = src.seqMeta[i].action
			} else {
				item.line = lineOf(c)
			}
			k, ok := uniqueKey(key, item)
			m := itemMeta(src, i, c)
			if !ok || k == "" {
				keyed = false
				out.Content = append(out.Content, clone(c))
				if fromOverlay {
					m.action = ActionAdd
				}
				meta = append(meta, m)
				continue
			}
			if pos, exists := index[k]; exists {
				prev := Contributor{File: meta[pos].file, Line: meta[pos].line, Action: meta[pos].action, Value: render(out.Content[pos])}
				out.Content[pos] = clone(c)
				m.action = ActionOverride
				m.prev = []Contributor{prev}
				meta[pos] = m
				continue
			}
			index[k] = len(out.Content)
			out.Content = append(out.Content, clone(c))
			if fromOverlay {
				m.action = ActionAdd
			}
			meta = append(meta, m)
		}
	}
	add(base, bn, false)
	add(over, on, true)
	cert := evidence.Proven
	if !keyed {
		cert = evidence.Unknown
	}
	return &val{
		node:      out,
		file:      over.file,
		line:      over.line,
		action:    ActionAppend,
		seqMeta:   meta,
		certainty: cert,
	}
}

func itemMeta(src *val, i int, c *yaml.Node) seqMeta {
	if i < len(src.seqMeta) {
		return src.seqMeta[i]
	}
	return seqMeta{file: src.file, line: lineOf(c), action: ActionSource}
}

func uniqueKey(field string, item *val) (string, bool) {
	switch field {
	case "ports":
		return portUniqueKey(item)
	case "volumes":
		return volumeUniqueKey(item)
	case "secrets", "configs":
		return namedResourceKey(item)
	case "environment":
		return envItemKey(item)
	case "depends_on":
		return dependsOnKey(item)
	default:
		return "", false
	}
}

func portUniqueKey(item *val) (string, bool) {
	n := deref(item.node)
	if n == nil {
		return "", false
	}
	ip, published, target, protocol := "", "", "", "tcp"
	if n.Kind == yaml.MappingNode || len(item.kids) > 0 {
		ip = mappingScalar(item, "host_ip", "ip")
		published = mappingScalar(item, "published")
		target = mappingScalar(item, "target")
		if p := mappingScalar(item, "protocol"); p != "" {
			protocol = strings.ToLower(p)
		}
		return "p|" + ip + "|" + target + "|" + published + "|" + protocol, target != "" || published != ""
	}
	s := strings.TrimSpace(n.Value)
	if s == "" {
		return "", false
	}
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		proto := strings.ToLower(s[i+1:])
		if proto == "tcp" || proto == "udp" || proto == "sctp" {
			protocol = proto
			s = s[:i]
		}
	}
	hostIP, pub, tgt, ok := splitPortShort(s)
	if !ok {
		return "", false
	}
	return "p|" + hostIP + "|" + tgt + "|" + pub + "|" + protocol, true
}

func splitPortShort(s string) (hostIP, published, target string, ok bool) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", "", false
		}
		hostIP = s[1:end]
		rest := s[end+1:]
		if rest == "" || rest[0] != ':' {
			return "", "", "", false
		}
		parts := strings.Split(rest[1:], ":")
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

func volumeUniqueKey(item *val) (string, bool) {
	n := deref(item.node)
	if n == nil {
		return "", false
	}
	if n.Kind == yaml.MappingNode || len(item.kids) > 0 {
		t := mappingScalar(item, "target")
		return "v|" + t, t != ""
	}
	t := shortvol.Target(n.Value)
	return "v|" + t, t != ""
}

func namedResourceKey(item *val) (string, bool) {
	n := deref(item.node)
	if n == nil {
		return "", false
	}
	if n.Kind == yaml.MappingNode || len(item.kids) > 0 {
		src := mappingScalar(item, "source")
		return "n|" + src, src != ""
	}
	s := strings.TrimSpace(n.Value)
	return "n|" + s, s != ""
}

func envItemKey(item *val) (string, bool) {
	n := deref(item.node)
	if n == nil {
		return "", false
	}
	if n.Kind == yaml.MappingNode || len(item.kids) > 0 {
		if len(item.order) == 1 {
			return "e|" + item.order[0], true
		}
		return "", false
	}
	s := strings.TrimSpace(n.Value)
	name, _, _ := strings.Cut(s, "=")
	name = strings.TrimSpace(name)
	return "e|" + name, name != ""
}

func dependsOnKey(item *val) (string, bool) {
	n := deref(item.node)
	if n == nil {
		return "", false
	}
	if n.Kind == yaml.MappingNode || len(item.kids) > 0 {
		if len(item.order) >= 1 {
			return "d|" + item.order[0], true
		}
		return "", false
	}
	s := strings.TrimSpace(n.Value)
	return "d|" + s, s != ""
}

func mappingScalar(item *val, names ...string) string {
	if item == nil || item.kids == nil {
		return ""
	}
	for _, name := range names {
		if c, ok := item.kids[name]; ok {
			return strings.TrimSpace(render(c.node))
		}
	}
	return ""
}
