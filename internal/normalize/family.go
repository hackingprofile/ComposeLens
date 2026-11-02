// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"strings"

	"composelens/internal/idpath"
)

// DualFormPath reports whether a merge path belongs to a field family this
// package canonicalizes (ports, volumes, labels, command, entrypoint,
// healthcheck.test). environment / env_file are not dual-form here.
func DualFormPath(path string, known []string) bool {
	_, ok := FamilyRoot(path, known)
	return ok
}

// FamilyRoot returns the canonical family path (for example services.web.ports)
// for a merge path under a dual-form field.
func FamilyRoot(path string, known []string) (string, bool) {
	svc, rest, ok := idpath.Parse(path, known)
	if !ok || rest == "" {
		return "", false
	}
	switch {
	case rest == ".ports" || strings.HasPrefix(rest, ".ports[") || strings.HasPrefix(rest, ".ports."):
		return idpath.Join(svc, "ports"), true
	case rest == ".volumes" || strings.HasPrefix(rest, ".volumes[") || strings.HasPrefix(rest, ".volumes."):
		return idpath.Join(svc, "volumes"), true
	case rest == ".labels" || strings.HasPrefix(rest, ".labels[") || strings.HasPrefix(rest, ".labels."):
		return idpath.Join(svc, "labels"), true
	case rest == ".command" || strings.HasPrefix(rest, ".command[") || strings.HasPrefix(rest, ".command."):
		return idpath.Join(svc, "command"), true
	case rest == ".entrypoint" || strings.HasPrefix(rest, ".entrypoint[") || strings.HasPrefix(rest, ".entrypoint."):
		return idpath.Join(svc, "entrypoint"), true
	case rest == ".healthcheck.test" || strings.HasPrefix(rest, ".healthcheck.test[") || strings.HasPrefix(rest, ".healthcheck.test."):
		return idpath.Join(svc, "healthcheck.test"), true
	default:
		return "", false
	}
}

// FamilyDisplay returns the canonical string for one dual-form family on a service.
func FamilyDisplay(s Service, root string) (string, bool, bool) {
	switch {
	case strings.HasSuffix(root, ".ports"):
		return DisplayPorts(s.Ports), len(s.Ports) > 0, portsSecret(s.Ports)
	case strings.HasSuffix(root, ".volumes"):
		return DisplayVolumes(s.Volumes), len(s.Volumes) > 0, volumesSecret(s.Volumes)
	case strings.HasSuffix(root, ".labels"):
		return DisplayLabels(s.Labels), len(s.Labels.Pairs) > 0, s.Labels.Provenance.Secret
	case strings.HasSuffix(root, ".command"):
		if s.Command == nil {
			return "", false, false
		}
		return DisplayCommand(s.Command), true, s.Command.Provenance.Secret
	case strings.HasSuffix(root, ".entrypoint"):
		if s.Entrypoint == nil {
			return "", false, false
		}
		return DisplayCommand(s.Entrypoint), true, s.Entrypoint.Provenance.Secret
	case strings.HasSuffix(root, ".healthcheck.test"):
		if s.Healthcheck == nil {
			return "", false, false
		}
		return DisplayHealthcheck(s.Healthcheck), true, s.Healthcheck.Provenance.Secret
	default:
		return "", false, false
	}
}

func FamilyEqual(a, b Service, root string) bool {
	switch {
	case strings.HasSuffix(root, ".ports"):
		return PortsEqual(a.Ports, b.Ports)
	case strings.HasSuffix(root, ".volumes"):
		return VolumesEqual(a.Volumes, b.Volumes)
	case strings.HasSuffix(root, ".labels"):
		return LabelsEqual(a.Labels, b.Labels)
	case strings.HasSuffix(root, ".command"):
		return CommandEqual(a.Command, b.Command)
	case strings.HasSuffix(root, ".entrypoint"):
		return CommandEqual(a.Entrypoint, b.Entrypoint)
	case strings.HasSuffix(root, ".healthcheck.test"):
		return HealthcheckEqual(a.Healthcheck, b.Healthcheck)
	default:
		return false
	}
}

func FamilySource(s Service, root string) string {
	switch {
	case strings.HasSuffix(root, ".ports"):
		if len(s.Ports) == 0 {
			return ""
		}
		return s.Ports[0].Provenance.Source
	case strings.HasSuffix(root, ".volumes"):
		if len(s.Volumes) == 0 {
			return ""
		}
		return s.Volumes[0].Provenance.Source
	case strings.HasSuffix(root, ".labels"):
		return s.Labels.Provenance.Source
	case strings.HasSuffix(root, ".command"):
		if s.Command == nil {
			return ""
		}
		return s.Command.Provenance.Source
	case strings.HasSuffix(root, ".entrypoint"):
		if s.Entrypoint == nil {
			return ""
		}
		return s.Entrypoint.Provenance.Source
	case strings.HasSuffix(root, ".healthcheck.test"):
		if s.Healthcheck == nil {
			return ""
		}
		return s.Healthcheck.Provenance.Source
	default:
		return ""
	}
}

func portsSecret(ports []Port) bool {
	for _, p := range ports {
		if p.Provenance.Secret {
			return true
		}
	}
	return false
}

func volumesSecret(vols []Volume) bool {
	for _, v := range vols {
		if v.Provenance.Secret {
			return true
		}
	}
	return false
}
