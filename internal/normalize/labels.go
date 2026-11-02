// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"sort"
	"strings"

	"composelens/internal/merge"
)

func parseLabels(fields []merge.Field, svc string) Labels {
	path := servicePrefix(svc, "labels")
	if hasSequenceItems(fields, path) {
		return parseLabelsList(fields, path)
	}
	return parseLabelsMap(fields, path)
}

func parseLabelsList(fields []merge.Field, path string) Labels {
	idxs := sequenceIndices(fields, path)
	parent, _ := fieldByPath(fields, path)
	seen := map[string]Label{}
	order := make([]string, 0, len(idxs))
	secret := parent.Secret
	for _, i := range idxs {
		item, ok := fieldByPath(fields, itemPath(path, i))
		if !ok {
			continue
		}
		if item.Secret {
			secret = true
		}
		key, val, ok := splitLabelItem(item.Value)
		if !ok {
			return Labels{Provenance: unknownProv(item.Value, "labels list item could not be parsed as KEY or KEY=VALUE", item.Winner, item.Line, secretish("", item.Value, item.Secret))}
		}
		lab := Label{
			Key:        key,
			Value:      val,
			Provenance: provenProv(item.Winner, item.Line, secretish(key, val, item.Secret)),
		}
		if _, exists := seen[key]; !exists {
			order = append(order, key)
		}
		seen[key] = lab
	}
	pairs := make([]Label, 0, len(order))
	for _, k := range order {
		pairs = append(pairs, seen[k])
	}
	sort.Slice(pairs, func(i, j int) bool { return pairs[i].Key < pairs[j].Key })
	src := parent.Winner
	line := parent.Line
	if src == "" && len(pairs) > 0 {
		src = pairs[0].Provenance.Source
		line = pairs[0].Provenance.Line
	}
	return Labels{
		Pairs:      pairs,
		Provenance: provenProv(src, line, secret),
	}
}

func parseLabelsMap(fields []merge.Field, path string) Labels {
	prefix := path + "."
	type pair struct {
		key string
		lab Label
	}
	var collected []pair
	secret := false
	src := ""
	line := 0
	for _, f := range fields {
		if f.Path == path || !strings.HasPrefix(f.Path, prefix) {
			continue
		}
		if strings.Contains(strings.TrimPrefix(f.Path, prefix), "[") {
			continue
		}
		key := strings.TrimPrefix(f.Path, prefix)
		if key == "" {
			continue
		}
		if f.Secret {
			secret = true
		}
		if src == "" {
			src = f.Winner
			line = f.Line
		}
		collected = append(collected, pair{key: key, lab: Label{
			Key:        key,
			Value:      f.Value,
			Provenance: provenProv(f.Winner, f.Line, secretish(key, f.Value, f.Secret)),
		}})
	}
	if len(collected) == 0 {
		return Labels{}
	}
	sort.Slice(collected, func(i, j int) bool { return collected[i].key < collected[j].key })
	pairs := make([]Label, 0, len(collected))
	for _, p := range collected {
		pairs = append(pairs, p.lab)
	}
	return Labels{Pairs: pairs, Provenance: provenProv(src, line, secret)}
}

func splitLabelItem(s string) (key, val string, ok bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", "", false
	}
	k, v, found := strings.Cut(s, "=")
	if !found {
		return s, "", true
	}
	if k == "" {
		return "", "", false
	}
	return k, v, true
}

func LabelsEqual(a, b Labels) bool {
	if !comparable(a.Provenance) || !comparable(b.Provenance) {
		if len(a.Pairs) == 0 && len(b.Pairs) == 0 {
			return unknownEqual(a.Provenance, b.Provenance) || (a.Provenance.Raw == "" && b.Provenance.Raw == "" && a.Provenance.Reason == b.Provenance.Reason)
		}
		return false
	}
	if len(a.Pairs) != len(b.Pairs) {
		return false
	}
	am := map[string]string{}
	for _, p := range a.Pairs {
		am[p.Key] = p.Value
	}
	for _, p := range b.Pairs {
		if am[p.Key] != p.Value {
			return false
		}
	}
	return true
}

func DisplayLabels(l Labels) string {
	if !comparable(l.Provenance) && l.Provenance.Raw != "" {
		return "unknown:" + l.Provenance.Raw
	}
	parts := make([]string, 0, len(l.Pairs))
	for _, p := range l.Pairs {
		parts = append(parts, p.Key+"="+p.Value)
	}
	return strings.Join(parts, ", ")
}
