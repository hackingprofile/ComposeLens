// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"

	"composelens/internal/safety"

	"gopkg.in/yaml.v3"
)

type decodeBudget struct {
	nodes int
}

func (b *decodeBudget) add() error {
	b.nodes++
	if b.nodes > safety.MaxYAMLNodes {
		return &Error{Kind: KindTooManyNodes, Message: "policy structure exceeds the node bound"}
	}
	return nil
}

func decodeJSONObject(raw []byte) (map[string]any, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	b := &decodeBudget{}
	val, err := readJSON(dec, 1, b)
	if err != nil {
		return nil, err
	}
	m, ok := val.(map[string]any)
	if !ok {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, &Error{Kind: KindTrailing, Message: "policy file has trailing content"}
	}
	return m, nil
}

func readJSON(dec *json.Decoder, depth int, b *decodeBudget) (any, error) {
	if depth > safety.MaxYAMLDepth {
		return nil, &Error{Kind: KindTooDeep, Message: "policy structure exceeds the depth bound"}
	}
	if err := b.add(); err != nil {
		return nil, err
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			return readJSONObject(dec, depth, b)
		case '[':
			return readJSONArray(dec, depth, b)
		default:
			return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
		}
	case nil, bool, float64, string:
		return t, nil
	default:
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
}

func readJSONObject(dec *json.Decoder, depth int, b *decodeBudget) (map[string]any, error) {
	out := map[string]any{}
	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
		}
		key, ok := tok.(string)
		if !ok {
			return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
		}
		if err := b.add(); err != nil {
			return nil, err
		}
		if _, exists := out[key]; exists {
			return nil, &Error{Kind: KindDuplicateField, Message: "duplicate field " + label(key)}
		}
		val, err := readJSON(dec, depth+1, b)
		if err != nil {
			return nil, err
		}
		out[key] = val
	}
	end, err := dec.Token()
	if err != nil {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	if d, ok := end.(json.Delim); !ok || d != '}' {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	return out, nil
}

func readJSONArray(dec *json.Decoder, depth int, b *decodeBudget) ([]any, error) {
	var out []any
	for dec.More() {
		val, err := readJSON(dec, depth+1, b)
		if err != nil {
			return nil, err
		}
		out = append(out, val)
	}
	end, err := dec.Token()
	if err != nil {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	if d, ok := end.(json.Delim); !ok || d != ']' {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	return out, nil
}

func decodeYAMLMapping(raw []byte) (map[string]any, error) {
	dec := yaml.NewDecoder(bytes.NewReader(raw))
	var first yaml.Node
	if err := dec.Decode(&first); err != nil {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	var second yaml.Node
	if err := dec.Decode(&second); err == nil {
		return nil, &Error{Kind: KindMultiDoc, Message: "policy file contains more than one document"}
	} else if err != io.EOF {
		return nil, &Error{Kind: KindTrailing, Message: "policy file has trailing content"}
	}
	if err := inspectYAML(&first, 0, &decodeBudget{}); err != nil {
		return nil, err
	}
	target := &first
	if first.Kind == yaml.DocumentNode && len(first.Content) > 0 {
		target = first.Content[0]
	}
	if target == nil || target.Kind != yaml.MappingNode {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	var top map[string]any
	if err := target.Decode(&top); err != nil {
		return nil, &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	return top, nil
}

func inspectYAML(n *yaml.Node, depth int, b *decodeBudget) error {
	if n == nil {
		return nil
	}
	if err := b.add(); err != nil {
		return err
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return &Error{Kind: KindUnsupported, Message: "YAML anchors and aliases are not allowed"}
	}
	if !yamlTagAllowed(n.Tag) {
		return &Error{Kind: KindUnsupported, Message: "YAML merge keys and custom tags are not allowed"}
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return &Error{Kind: KindMalformed, Message: "policy file is malformed"}
		}
		if len(n.Content) != 1 {
			return &Error{Kind: KindMultiDoc, Message: "policy file contains more than one document"}
		}
		return inspectYAML(n.Content[0], depth, b)
	case yaml.SequenceNode:
		if depth+1 > safety.MaxYAMLDepth {
			return &Error{Kind: KindTooDeep, Message: "policy structure exceeds the depth bound"}
		}
		for _, c := range n.Content {
			if err := inspectYAML(c, depth+1, b); err != nil {
				return err
			}
		}
	case yaml.MappingNode:
		if depth+1 > safety.MaxYAMLDepth {
			return &Error{Kind: KindTooDeep, Message: "policy structure exceeds the depth bound"}
		}
		seen := map[string]struct{}{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			keyNode := n.Content[i]
			if yamlMappingKey(keyNode) == "<<" || keyNode.Tag == "!!merge" {
				return &Error{Kind: KindUnsupported, Message: "YAML merge keys and custom tags are not allowed"}
			}
			key := yamlMappingKey(keyNode)
			if _, ok := seen[key]; ok {
				return &Error{Kind: KindDuplicateField, Message: "duplicate field " + label(key)}
			}
			seen[key] = struct{}{}
			if err := inspectYAML(keyNode, depth+1, b); err != nil {
				return err
			}
			if err := inspectYAML(n.Content[i+1], depth+1, b); err != nil {
				return err
			}
		}
	case yaml.ScalarNode:
	default:
		return &Error{Kind: KindMalformed, Message: "policy file is malformed"}
	}
	return nil
}

func yamlTagAllowed(tag string) bool {
	if tag == "" || tag == "!" {
		return true
	}
	if tag == "!!merge" {
		return false
	}
	return strings.HasPrefix(tag, "!!")
}

func yamlMappingKey(n *yaml.Node) string {
	if n == nil {
		return ""
	}
	if n.Kind == yaml.AliasNode {
		return ""
	}
	return n.Value
}
