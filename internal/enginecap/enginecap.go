// SPDX-License-Identifier: Apache-2.0

package enginecap

import (
	"composelens/internal/evidence"
)

const (
	Schema = "composelens.enginecap.v0"
	Window = "docker-compose-plugin-v2"

	SupportRecognized  = "recognized"
	SupportUnsupported = "unsupported"
	SupportUnknown     = "unknown"
	SupportAbsent      = "engine-absent"
	SupportError       = "engine-error"

	CapComposeConfig  = "compose-config"
	CapInterpolation  = "compose-interpolation"
	CapInclude        = "compose-include"
	CapExtends        = "compose-extends-mapping"
	CapProfiles       = "compose-profiles"
	CapUniqueKeyMerge = "unique-key-sequence-merge"
)

// Report is an honest capability map for a detected Compose engine.
// Unverified engine behaviors are unknown — never assumed.
type Report struct {
	Schema        string       `json:"schema"`
	Window        string       `json:"window"`
	Support       string       `json:"support"`
	EngineVersion string       `json:"engineVersion,omitempty"`
	Detail        string       `json:"detail,omitempty"`
	Capabilities  []Capability `json:"capabilities"`
	Evidence      string       `json:"evidence"`
	Certainty     string       `json:"certainty"`
	Disclaimer    string       `json:"disclaimer"`
}

type Capability struct {
	ID        string `json:"id"`
	State     string `json:"state"`
	Certainty string `json:"certainty"`
	Detail    string `json:"detail,omitempty"`
}

func Assess(version string, captureState string) Report {
	r := Report{
		Schema:        Schema,
		Window:        Window,
		EngineVersion: version,
		Disclaimer:    "engine capability map -- not a differential; unverified engine behaviors are unknown",
		Evidence:      evidence.Known,
		Certainty:     evidence.Proven,
	}
	switch captureState {
	case "engine-absent":
		r.Support = SupportAbsent
		r.Detail = "docker CLI not found on PATH"
		r.Evidence = evidence.Absent
		r.Capabilities = unknownCaps("engine absent")
		return r
	case "engine-error":
		r.Support = SupportError
		r.Detail = "engine command failed"
		r.Capabilities = unknownCaps("engine error")
		return r
	}

	maj, ok := major(version)
	if !ok {
		r.Support = SupportUnknown
		r.Detail = "engine version string not parsed"
		r.Certainty = evidence.Unknown
		r.Capabilities = unknownCaps("version unparsed")
		return r
	}
	if maj < 2 {
		r.Support = SupportUnsupported
		r.Detail = "engine version outside Docker Compose v2+ window (docs/compatibility.md); Compose v1 is unsupported"
		r.Capabilities = unknownCaps("out of window")
		return r
	}
	r.Support = SupportRecognized
	r.Detail = "recognized Docker Compose v2+ family; not a verified multi-version matrix"
	cfg := Capability{ID: CapComposeConfig, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: "doctor does not run config"}
	if captureState == "captured" {
		cfg.State = evidence.Known
		cfg.Certainty = evidence.Proven
		cfg.Detail = "live docker compose config succeeded"
	}
	r.Capabilities = []Capability{
		cfg,
		{ID: CapInterpolation, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: "doctor does not execute differential or config; capability is recognized, not runtime-verified"},
		{ID: CapInclude, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: "doctor does not execute differential or config; capability is recognized, not runtime-verified"},
		{ID: CapExtends, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: "doctor does not execute differential or config; capability is recognized, not runtime-verified"},
		{ID: CapProfiles, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: "doctor does not execute differential or config; capability is recognized, not runtime-verified"},
		{ID: CapUniqueKeyMerge, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: "file overlay unique-key-merges ports/volumes/secrets/configs; not an engine differential"},
	}
	return r
}

func FromDetect(state, version string) Report {
	switch state {
	case evidence.Absent:
		return Assess(version, "engine-absent")
	case evidence.Unknown:
		return Assess(version, "")
	default:
		return Assess(version, "")
	}
}

func unknownCaps(detail string) []Capability {
	ids := []string{CapComposeConfig, CapInterpolation, CapInclude, CapExtends, CapProfiles, CapUniqueKeyMerge}
	out := make([]Capability, 0, len(ids))
	for _, id := range ids {
		out = append(out, Capability{ID: id, State: evidence.Unknown, Certainty: evidence.Unknown, Detail: detail})
	}
	return out
}
