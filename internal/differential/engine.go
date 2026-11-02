// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"strings"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/discover"
	"composelens/internal/explain"
	"composelens/internal/merge"
	"composelens/internal/profiles"
)

// ParseConfig turns a live `docker compose config` YAML document into the same
// stage-shaped input used for comparison. Interpolation is not re-run: the
// engine output is already resolved. Dump-escaping (`$$` → `$`) is applied
// once so escaped literals compare as the engine's runtime values.
func ParseConfig(raw string) (explain.Input, error) {
	if strings.TrimSpace(raw) == "" {
		return explain.Input{}, nil
	}
	d, err := composeparse.Parse(discover.File{Path: "engine-config", Bytes: []byte(raw), Origin: "engine"})
	if err != nil {
		return explain.Input{}, err
	}
	deescapeDump(d.Root)
	fields := merge.Documents([]*composeparse.Document{d}, nil)
	var enabled []profiles.Service
	for _, name := range merge.ServiceNames(fields) {
		enabled = append(enabled, profiles.Service{
			Name:  name,
			State: profiles.StateEnabled,
		})
	}
	cen, err := containerenv.Resolve(fields, map[string]string{}, nil)
	if err != nil {
		return explain.Input{}, err
	}
	return explain.Input{
		Merge:     fields,
		Profiles:  enabled,
		Container: cen,
	}, nil
}

// deescapeDump applies one dump unescape (`$$` → `$`) to string scalars.
// It is not interpolation: unset `$VAR` in the dump stays `$VAR`.
func deescapeDump(n *yaml.Node) {
	if n == nil {
		return
	}
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		deescapeDump(n.Alias)
		return
	}
	switch n.Kind {
	case yaml.DocumentNode, yaml.SequenceNode:
		for _, c := range n.Content {
			deescapeDump(c)
		}
	case yaml.MappingNode:
		for i := 1; i < len(n.Content); i += 2 {
			deescapeDump(n.Content[i])
		}
	case yaml.ScalarNode:
		if !dumpStringScalar(n) || !strings.Contains(n.Value, "$$") {
			return
		}
		n.Value = strings.ReplaceAll(n.Value, "$$", "$")
	}
}

func dumpStringScalar(n *yaml.Node) bool {
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	switch n.Tag {
	case "!!bool", "!!int", "!!float", "!!null", "!!binary", "!!timestamp", "!!merge":
		return false
	default:
		return true
	}
}
