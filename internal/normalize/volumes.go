// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"

	"composelens/internal/merge"
	"composelens/internal/shortvol"
)

var volumeTopKeys = map[string]struct{}{
	"type":      {},
	"source":    {},
	"target":    {},
	"read_only": {},
	"bind":      {},
	"volume":    {},
	"tmpfs":     {},
}

var knownModeTokens = map[string]struct{}{
	"ro": {}, "rw": {},
	"z": {}, "Z": {},
	"consistent": {}, "delegated": {}, "cached": {},
	"shared": {}, "rshared": {}, "slave": {}, "rslave": {}, "private": {}, "rprivate": {},
}

func parseVolumes(fields []merge.Field, svc string) []Volume {
	listPath := servicePrefix(svc, "volumes")
	idxs := sequenceIndices(fields, listPath)
	if len(idxs) == 0 {
		return nil
	}
	out := make([]Volume, 0, len(idxs))
	for _, i := range idxs {
		ip := itemPath(listPath, i)
		item, kids, ok := itemOrChildren(fields, ip)
		if !ok {
			continue
		}
		if isLongVolume(item.Value, kids) {
			out = append(out, parseVolumeLong(item, kids))
			continue
		}
		out = append(out, parseVolumeShort(item))
	}
	return out
}

func isLongVolume(value string, kids map[string]string) bool {
	if len(kids) == 0 {
		return strings.HasPrefix(strings.TrimSpace(value), "{")
	}
	for k := range kids {
		base, _, _ := strings.Cut(k, ".")
		if _, ok := volumeTopKeys[base]; ok {
			return true
		}
	}
	return strings.HasPrefix(strings.TrimSpace(value), "{")
}

func parseVolumeLong(item merge.Field, kids map[string]string) Volume {
	secret := secretish("", item.Value, item.Secret)
	v := Volume{
		Type:        strings.ToLower(strings.TrimSpace(kids["type"])),
		Source:      strings.TrimSpace(kids["source"]),
		Target:      strings.TrimSpace(kids["target"]),
		SELinux:     strings.TrimSpace(kids["bind.selinux"]),
		Propagation: strings.TrimSpace(kids["bind.propagation"]),
		Subpath:     strings.TrimSpace(kids["volume.subpath"]),
		TmpfsSize:   strings.TrimSpace(kids["tmpfs.size"]),
		TmpfsMode:   strings.TrimSpace(kids["tmpfs.mode"]),
		CreateHost:  strings.ToLower(strings.TrimSpace(kids["bind.create_host_path"])),
		Provenance:  provenProv(item.Winner, item.Line, secret),
	}
	if ro, ok := kids["read_only"]; ok {
		b, parsed := parseBool(ro)
		if !parsed {
			v.Provenance = unknownProv(item.Value, "volumes read_only is not a documented boolean", item.Winner, item.Line, secret)
			return v
		}
		v.ReadOnly = b
	}
	if nc, ok := kids["volume.nocopy"]; ok {
		b, parsed := parseBool(nc)
		if !parsed {
			v.Provenance = unknownProv(item.Value, "volumes volume.nocopy is not a documented boolean", item.Winner, item.Line, secret)
			return v
		}
		v.Nocopy = b
	}
	var extra []string
	for _, k := range sortedKeys(kids) {
		if volumeKeyKnown(k) {
			continue
		}
		extra = append(extra, k)
	}
	v.Extra = extra
	if v.Target == "" {
		v.Provenance = unknownProv(item.Value, "volumes long form missing target", item.Winner, item.Line, secret)
		return v
	}
	if v.Type == "" {
		v.Type = inferVolumeType(v.Source)
		v.Provenance = inferredProv(item.Winner, item.Line, secret, "volumes long form omitted type; inferred from source")
	}
	if len(extra) > 0 {
		v.Provenance = unknownProv(item.Value, "volumes long-form extra keys are not a documented lossless conversion: "+strings.Join(extra, ","), item.Winner, item.Line, secret)
	}
	return v
}

func volumeKeyKnown(k string) bool {
	switch k {
	case "type", "source", "target", "read_only",
		"bind", "bind.propagation", "bind.create_host_path", "bind.selinux",
		"volume", "volume.nocopy", "volume.subpath",
		"tmpfs", "tmpfs.size", "tmpfs.mode":
		return true
	default:
		return false
	}
}

func parseVolumeShort(item merge.Field) Volume {
	raw := strings.TrimSpace(item.Value)
	secret := secretish("", raw, item.Secret)
	spec, ok := shortvol.Parse(raw)
	if !ok {
		return Volume{Provenance: unknownProv(raw, "volumes short syntax could not be parsed without guessing", item.Winner, item.Line, secret)}
	}
	v := Volume{
		Source:      spec.Source,
		Target:      spec.Target,
		Type:        inferVolumeType(spec.Source),
		Provenance:  provenProv(item.Winner, item.Line, secret),
		ShortSyntax: true,
	}
	v.Provenance.Raw = raw
	if spec.Mode != "" {
		if !applyVolumeMode(&v, spec.Mode, item, secret) {
			return v
		}
	}
	return v
}

func applyVolumeMode(v *Volume, mode string, item merge.Field, secret bool) bool {
	for _, tok := range strings.Split(mode, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if _, ok := knownModeTokens[tok]; !ok {
			v.Provenance = unknownProv(item.Value, "volumes short mode token is not a documented lossless conversion: "+tok, item.Winner, item.Line, secret)
			v.Extra = append(v.Extra, tok)
			return false
		}
		switch tok {
		case "ro":
			v.ReadOnly = true
		case "rw":
			v.ReadOnly = false
		case "z", "Z":
			v.SELinux = tok
		case "shared", "rshared", "slave", "rslave", "private", "rprivate":
			v.Propagation = tok
		default:
			// consistency / delegated / cached: host-consistency flags with no
			// documented long-form bind equivalent in the fields we model.
			v.Provenance = unknownProv(item.Value, "volumes consistency mode has no documented lossless long-form pair: "+tok, item.Winner, item.Line, secret)
			v.Extra = append(v.Extra, tok)
			return false
		}
	}
	return true
}

func inferVolumeType(source string) string {
	if source == "" {
		return "volume"
	}
	if strings.HasPrefix(source, ".") || strings.HasPrefix(source, "/") || strings.HasPrefix(source, "~") {
		return "bind"
	}
	if strings.Contains(source, `\`) || shortvol.WindowsDrive(source) {
		return "bind"
	}
	return "volume"
}

func VolumesEqual(a, b []Volume) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !VolumeEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

func VolumeEqual(a, b Volume) bool {
	if !comparable(a.Provenance) || !comparable(b.Provenance) {
		return unknownEqual(a.Provenance, b.Provenance)
	}
	return a.Type == b.Type &&
		a.Source == b.Source &&
		a.Target == b.Target &&
		a.ReadOnly == b.ReadOnly &&
		a.SELinux == b.SELinux &&
		a.Propagation == b.Propagation &&
		a.Nocopy == b.Nocopy &&
		a.Subpath == b.Subpath &&
		a.TmpfsSize == b.TmpfsSize &&
		a.TmpfsMode == b.TmpfsMode &&
		createHostEqual(a, b) &&
		strings.Join(a.Extra, ",") == strings.Join(b.Extra, ",")
}

func DisplayVolume(v Volume) string {
	if !comparable(v.Provenance) && v.Provenance.Raw != "" {
		return "unknown:" + v.Provenance.Raw
	}
	var b strings.Builder
	b.WriteString("type=")
	b.WriteString(v.Type)
	if v.Source != "" {
		b.WriteString(" source=")
		b.WriteString(v.Source)
	}
	b.WriteString(" target=")
	b.WriteString(v.Target)
	if v.ReadOnly {
		b.WriteString(" read_only=true")
	}
	if v.SELinux != "" {
		b.WriteString(" selinux=")
		b.WriteString(v.SELinux)
	}
	if v.Propagation != "" {
		b.WriteString(" propagation=")
		b.WriteString(v.Propagation)
	}
	if v.Nocopy {
		b.WriteString(" nocopy=true")
	}
	if v.Subpath != "" {
		b.WriteString(" subpath=")
		b.WriteString(v.Subpath)
	}
	if v.CreateHost != "" {
		b.WriteString(" create_host_path=")
		b.WriteString(v.CreateHost)
	}
	if v.TmpfsSize != "" {
		b.WriteString(" tmpfs.size=")
		b.WriteString(v.TmpfsSize)
	}
	if v.TmpfsMode != "" {
		b.WriteString(" tmpfs.mode=")
		b.WriteString(v.TmpfsMode)
	}
	return b.String()
}

func DisplayVolumes(vols []Volume) string {
	parts := make([]string, 0, len(vols))
	for _, v := range vols {
		parts = append(parts, DisplayVolume(v))
	}
	return strings.Join(parts, "; ")
}

// createHostEqual compares create_host_path. A short-syntax bind implies
// true, and engine releases differ in whether their long-form dump prints
// that default, so an unset value on a bind compared with a short-syntax
// bind counts as the implied true. An explicit false stays different.
func createHostEqual(a, b Volume) bool {
	if a.CreateHost == b.CreateHost {
		return true
	}
	if a.Type != "bind" || b.Type != "bind" || (!a.ShortSyntax && !b.ShortSyntax) {
		return false
	}
	implied := func(v Volume) bool { return v.CreateHost == "" || v.CreateHost == "true" }
	return implied(a) && implied(b)
}
