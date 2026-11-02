// SPDX-License-Identifier: Apache-2.0

package engineadapter

import (
	"sort"
	"strings"
	"unicode"

	"composelens/internal/redact"

	"gopkg.in/yaml.v3"
)

const redacted = "[redacted]"

func RedactEngineOutput(raw string) (string, []string) {
	if raw == "" {
		return "", nil
	}
	secrets := collectSecrets(raw)
	if len(secrets) == 0 {
		return raw, nil
	}
	sort.Slice(secrets, func(i, j int) bool { return len(secrets[i]) > len(secrets[j]) })
	out := raw
	for _, s := range secrets {
		if s == "" || s == redacted {
			continue
		}
		out = strings.ReplaceAll(out, s, redacted)
	}
	// Text replacement keeps the engine's bytes, but a withheld value that
	// starts a wrapped plain scalar would leave "[redacted]" opening a flow
	// sequence. When the engine YAML parsed and the replaced text does not,
	// redact the parsed scalars instead so the YAML stays valid.
	if mappingYAML(raw) && !mappingYAML(out) {
		if fixed, ok := redactNodes(raw, secrets); ok {
			out = fixed
		}
	}
	return out, secrets
}

func mappingYAML(s string) bool {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(s), &root); err != nil {
		return false
	}
	return len(root.Content) == 1 && root.Content[0].Kind == yaml.MappingNode
}

// redactNodes replaces every withheld value inside parsed scalars (keys and
// values) and re-serializes the document.
func redactNodes(raw string, secrets []string) (string, bool) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &root); err != nil {
		return "", false
	}
	var walk func(n *yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			for _, s := range secrets {
				if s != "" && s != redacted {
					n.Value = strings.ReplaceAll(n.Value, s, redacted)
				}
			}
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&root)
	b, err := yaml.Marshal(&root)
	if err != nil {
		return "", false
	}
	return string(b), true
}

func redactText(raw string) string {
	out, _ := RedactEngineOutput(raw)
	return out
}

func collectSecrets(raw string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" || s == redacted {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(raw), &root); err == nil {
		walkYAML(&root, "", add)
	}
	for _, tok := range tokens(raw) {
		if redact.LooksLikeSecret(tok) {
			add(tok)
		}
		if k, v, ok := strings.Cut(tok, "="); ok && redact.MustRedact(k, v) {
			add(v)
		}
	}
	return out
}

func walkYAML(n *yaml.Node, path string, add func(string)) {
	if n == nil {
		return
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for i, c := range n.Content {
			walkYAML(c, path, add)
			// ["--token", "VALUE"]: the item after a secret-named flag is secret.
			if c.Kind == yaml.ScalarNode && redact.SecretFlag(c.Value) && i+1 < len(n.Content) {
				if nx := n.Content[i+1]; nx.Kind == yaml.ScalarNode && !strings.HasPrefix(nx.Value, "-") {
					add(nx.Value)
				}
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			child := k
			if path != "" {
				child = path + "." + k
			}
			walkYAML(n.Content[i+1], child, add)
		}
	case yaml.ScalarNode:
		// A value under a secret-named key at any depth is secret.
		if redact.MustRedactAt(path, n.Value) {
			add(n.Value)
		}
		if k, v, ok := strings.Cut(n.Value, "="); ok && redact.MustRedact(strings.TrimSpace(k), strings.TrimSpace(v)) {
			add(strings.TrimSpace(v))
		}
	}
}

func tokens(raw string) []string {
	return strings.FieldsFunc(raw, func(r rune) bool {
		if unicode.IsSpace(r) {
			return true
		}
		switch r {
		case '"', '\'', '[', ']', '{', '}', ',', '|':
			return true
		default:
			return false
		}
	})
}
