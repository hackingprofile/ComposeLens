// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"

	"composelens/internal/merge"
)

func parseCommand(fields []merge.Field, svc, field string) *Command {
	path := servicePrefix(svc, field)
	if hasSequenceItems(fields, path) {
		vals, parent, ok := sequenceValues(fields, path)
		if !ok {
			return nil
		}
		secret := secretish(field, strings.Join(vals, " "), parent.Secret)
		for _, v := range vals {
			if secretish(field, v, false) {
				secret = true
			}
		}
		argv := append([]string{}, vals...)
		return &Command{
			Form:       FormExec,
			Argv:       argv,
			Provenance: provenProv(parent.Winner, parent.Line, secret),
		}
	}
	item, ok := fieldByPath(fields, path)
	if !ok {
		return nil
	}
	raw := item.Value
	if strings.TrimSpace(raw) == "[]" {
		return &Command{
			Form:       "unknown",
			Provenance: unknownProv(raw, field+" empty list vs string [] cannot be distinguished from merge flatten", item.Winner, item.Line, secretish(field, raw, item.Secret)),
		}
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		c := &Command{Provenance: unknownProv(raw, field+" mapping form is not a documented shell/exec conversion", item.Winner, item.Line, secretish(field, raw, item.Secret))}
		c.Form = "unknown"
		return c
	}
	if strings.HasPrefix(strings.TrimSpace(raw), "[") && !hasSequenceItems(fields, path) {
		c := &Command{Provenance: unknownProv(raw, field+" rendered list without indexed items is ambiguous", item.Winner, item.Line, secretish(field, raw, item.Secret))}
		c.Form = "unknown"
		return c
	}
	return &Command{
		Form:       FormShell,
		Shell:      raw,
		Provenance: provenProv(item.Winner, item.Line, secretish(field, raw, item.Secret)),
	}
}

func parseHealthcheck(fields []merge.Field, svc string) *Healthcheck {
	path := servicePrefix(svc, "healthcheck.test")
	if hasSequenceItems(fields, path) {
		vals, parent, ok := sequenceValues(fields, path)
		if !ok || len(vals) == 0 {
			return nil
		}
		secret := parent.Secret
		for _, v := range vals {
			if secretish("test", v, false) {
				secret = true
			}
		}
		kind := strings.ToUpper(strings.TrimSpace(vals[0]))
		switch kind {
		case KindCMD, KindCMDShell:
			return &Healthcheck{
				Kind:       kind,
				Args:       append([]string{}, vals[1:]...),
				Provenance: provenProv(parent.Winner, parent.Line, secret),
			}
		case KindNONE:
			if len(vals) != 1 {
				return &Healthcheck{Provenance: unknownProv(strings.Join(vals, " "), "healthcheck.test NONE must be a single-element list", parent.Winner, parent.Line, secret), Kind: "unknown"}
			}
			return &Healthcheck{
				Kind:       KindNONE,
				Provenance: provenProv(parent.Winner, parent.Line, secret),
			}
		default:
			return &Healthcheck{Provenance: unknownProv(strings.Join(vals, " "), "healthcheck.test list must start with CMD, CMD-SHELL, or NONE", parent.Winner, parent.Line, secret), Kind: "unknown"}
		}
	}
	item, ok := fieldByPath(fields, path)
	if !ok {
		return nil
	}
	raw := item.Value
	secret := secretish("test", raw, item.Secret)
	if strings.HasPrefix(strings.TrimSpace(raw), "{") {
		return &Healthcheck{Provenance: unknownProv(raw, "healthcheck.test mapping form is not documented", item.Winner, item.Line, secret), Kind: "unknown"}
	}
	// Compose Specification: a string is equivalent to CMD-SHELL followed by that string.
	return &Healthcheck{
		Kind:       KindCMDShell,
		Args:       []string{raw},
		Provenance: provenProv(item.Winner, item.Line, secret),
	}
}

func CommandEqual(a, b *Command) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !comparable(a.Provenance) || !comparable(b.Provenance) {
		return unknownEqual(a.Provenance, b.Provenance)
	}
	if a.Form != b.Form {
		return false
	}
	switch a.Form {
	case FormShell:
		return a.Shell == b.Shell
	case FormExec:
		if len(a.Argv) != len(b.Argv) {
			return false
		}
		for i := range a.Argv {
			if a.Argv[i] != b.Argv[i] {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func HealthcheckEqual(a, b *Healthcheck) bool {
	if a == nil && b == nil {
		return true
	}
	if a == nil || b == nil {
		return false
	}
	if !comparable(a.Provenance) || !comparable(b.Provenance) {
		return unknownEqual(a.Provenance, b.Provenance)
	}
	if a.Kind != b.Kind {
		return false
	}
	if len(a.Args) != len(b.Args) {
		return false
	}
	for i := range a.Args {
		if a.Args[i] != b.Args[i] {
			return false
		}
	}
	return true
}

func DisplayCommand(c *Command) string {
	if c == nil {
		return ""
	}
	if !comparable(c.Provenance) && c.Provenance.Raw != "" {
		return "unknown:" + c.Provenance.Raw
	}
	switch c.Form {
	case FormShell:
		return "form=shell value=" + c.Shell
	case FormExec:
		return "form=exec argv=[" + strings.Join(c.Argv, ", ") + "]"
	default:
		return "form=unknown"
	}
}

func DisplayHealthcheck(h *Healthcheck) string {
	if h == nil {
		return ""
	}
	if !comparable(h.Provenance) && h.Provenance.Raw != "" {
		return "unknown:" + h.Provenance.Raw
	}
	if h.Kind == KindNONE {
		return "kind=NONE"
	}
	if len(h.Args) == 0 {
		return "kind=" + h.Kind
	}
	return "kind=" + h.Kind + " args=[" + strings.Join(h.Args, ", ") + "]"
}
