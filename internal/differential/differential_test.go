// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/containerenv"
	"composelens/internal/engineadapter"
	"composelens/internal/evidence"
	"composelens/internal/explain"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/safety"
)

func TestCompareMatchImage(t *testing.T) {
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.image", Value: "alpine", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	eng := in
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.image")
	if row.State != StateMatch {
		t.Fatalf("%+v", row)
	}
}

func TestCompareDivergentImage(t *testing.T) {
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.image", Value: "nginx", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	eng := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.image", Value: "alpine", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.image")
	if row.State != StateDivergent || row.Internal != "nginx" || row.Engine != "alpine" {
		t.Fatalf("%+v", row)
	}
}

func TestCompareNestedNetworksOnlyEngine(t *testing.T) {
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.image", Value: "alpine", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	eng := explain.Input{
		Merge: []merge.Field{
			{Path: "services.web.image", Value: "alpine", Certainty: evidence.Proven},
			{Path: "services.web.networks.default", Value: "", Certainty: evidence.Proven},
		},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.networks")
	if row.State != StateOnlyEngine {
		t.Fatalf("%+v", row)
	}
	if row.Classification != ClassByDesign || row.Detail != DetailD3DefaultNetwork {
		t.Fatalf("D3 must classify implicit default networks %+v", row)
	}
}

func TestCompareOnlyEngineAndOnlyInternal(t *testing.T) {
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.hostname", Value: "box", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	eng := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.networks", Value: "{default=}", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	host := mustRow(t, rep, "services.web.hostname")
	if host.State != StateOnlyInternal {
		t.Fatalf("hostname %+v", host)
	}
	net := mustRow(t, rep, "services.web.networks")
	if net.State != StateOnlyEngine {
		t.Fatalf("networks %+v", net)
	}
	if net.Classification != ClassByDesign || net.Detail != DetailD3DefaultNetwork {
		t.Fatalf("D3 brace-bundle default networks %+v", net)
	}
	if host.Classification != "" {
		t.Fatalf("unrelated hostname only-internal must stay bare %+v", host)
	}
}

func TestCompareCanonicalPortsMatch(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n    ports:\n      - \"8080:80\"\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    ports:\n      - target: 80\n        published: \"8080\"\n        protocol: tcp\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.ports")
	if row.State != StateMatch {
		t.Fatalf("short vs long ports must match after canonicalization %+v", row)
	}
}

func TestCompareUncertainUnknownCertainty(t *testing.T) {
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.dns", Value: "[1.1.1.1]", Certainty: evidence.Unknown}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	eng := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.dns", Value: "[1.1.1.1]", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.dns")
	if row.State != StateUncertain {
		t.Fatalf("%+v", row)
	}
}

func TestCompareSecretDifferentDivergent(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	other := "other-secret"
	in := secretEnvInput(probe)
	eng := secretEnvInput(other)
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "web:API_TOKEN")
	if row.State != StateDivergent || row.Certainty != evidence.Proven || !row.Secret {
		t.Fatalf("different secrets must be proven divergent %+v", row)
	}
	assertSecretSafe(t, rep, probe, other)
}

func TestCompareSecretEqualMatch(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	in := secretEnvInput(probe)
	eng := secretEnvInput(probe)
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "web:API_TOKEN")
	if row.State != StateMatch || row.Certainty != evidence.Proven || !row.Secret {
		t.Fatalf("equal secrets must be proven match %+v", row)
	}
	if row.Detail != "" {
		t.Fatalf("match must not claim values were skipped %+v", row)
	}
	assertSecretSafe(t, rep, probe)
}

func TestCompareSecretPlaceholderUncertain(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	cases := []struct {
		name  string
		left  string
		right string
	}{
		{name: "engine-withheld", left: probe, right: "[redacted]"},
		{name: "internal-withheld", left: "[redacted]", right: probe},
		{name: "both-withheld", left: "[redacted]", right: "[redacted]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rep := CompareInputs(secretEnvInput(tc.left), secretEnvInput(tc.right), Meta{EngineState: engineadapter.StateCaptured})
			row := mustRow(t, rep, "web:API_TOKEN")
			if row.State != StateUncertain || row.Certainty != evidence.Unknown {
				t.Fatalf("placeholder must be typed uncertainty %+v", row)
			}
			assertSecretSafe(t, rep, probe)
		})
	}
}

func TestCompareSecretPresenceOnlySides(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	in := secretEnvInput(probe)
	empty := explain.Input{Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}}}
	onlyIn := CompareInputs(in, empty, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, onlyIn, "web:API_TOKEN")
	if row.State != StateOnlyInternal || row.Certainty != evidence.Proven || !row.Secret {
		t.Fatalf("only-internal %+v", row)
	}
	onlyEng := CompareInputs(empty, in, Meta{EngineState: engineadapter.StateCaptured})
	row = mustRow(t, onlyEng, "web:API_TOKEN")
	if row.State != StateOnlyEngine || row.Certainty != evidence.Proven || !row.Secret {
		t.Fatalf("only-engine %+v", row)
	}
	assertSecretSafe(t, onlyIn, probe)
	assertSecretSafe(t, onlyEng, probe)
}

func TestCompareSecretLeafPlaceholderNotFalseDivergent(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.hostname", Value: probe, Secret: true, Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	eng := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.hostname", Value: "[redacted]", Secret: true, Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.hostname")
	if row.State != StateUncertain || row.Certainty != evidence.Unknown || !row.Secret {
		t.Fatalf("withheld leaf must not be proven divergent %+v", row)
	}
	assertSecretSafe(t, rep, probe)
}

func TestCompareSecretLeafEqualMatch(t *testing.T) {
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.hostname", Value: probe, Secret: true, Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, in, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.hostname")
	if row.State != StateMatch || row.Certainty != evidence.Proven || !row.Secret {
		t.Fatalf("equal secret leaves %+v", row)
	}
	assertSecretSafe(t, rep, probe)
}

func secretEnvInput(value string) explain.Input {
	return explain.Input{
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
		Container: []containerenv.ServiceEnv{{
			Service: "web",
			Vars: []containerenv.Variable{{
				Service: "web", Key: "API_TOKEN", Value: value, State: containerenv.StateSet, Secret: true,
			}},
		}},
	}
}

func assertSecretSafe(t *testing.T, rep Report, probes ...string) {
	t.Helper()
	for i := range rep.Rows {
		r := rep.Rows[i]
		if !r.Secret {
			continue
		}
		if (r.Internal != "" && r.Internal != "[redacted]") || (r.Engine != "" && r.Engine != "[redacted]") {
			t.Fatalf("secret display leaked %+v", r)
		}
	}
	human := Human(rep)
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	blobs := []string{human, string(raw)}
	for _, probe := range probes {
		sum := sha256.Sum256([]byte(probe))
		fp := hex.EncodeToString(sum[:])
		for _, blob := range blobs {
			if probe != "" && strings.Contains(blob, probe) {
				t.Fatal("emitted raw secret")
			}
			if strings.Contains(blob, fp) {
				t.Fatal("emitted secret fingerprint")
			}
		}
		if err := safety.Guard([]byte(human), []string{probe}); err != nil {
			t.Fatal(err)
		}
		if err := safety.Guard(raw, []string{probe}); err != nil {
			t.Fatal(err)
		}
	}
}

func TestEngineAbsentDoesNotFabricate(t *testing.T) {
	in := explain.Input{
		Merge:    []merge.Field{{Path: "services.web.image", Value: "alpine", Certainty: evidence.Proven}},
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
	}
	rep := CompareInputs(in, explain.Input{}, Meta{EngineState: engineadapter.StateEngineAbsent})
	if len(rep.Rows) != 0 {
		t.Fatalf("fabricated rows %+v", rep.Rows)
	}
	if rep.EngineState != engineadapter.StateEngineAbsent {
		t.Fatalf("state %s", rep.EngineState)
	}
}

func TestParseConfigEngineYAML(t *testing.T) {
	raw := "services:\n  web:\n    image: alpine\n    ports:\n      - target: 80\n        published: \"8080\"\n        protocol: tcp\n"
	in, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range in.Merge {
		if f.Path == "services.web.image" && f.Value == "alpine" {
			found = true
		}
	}
	if !found {
		t.Fatalf("image missing %+v", in.Merge)
	}
}

func TestParseConfigDeescapesDumpDollars(t *testing.T) {
	raw := "services:\n  web:\n    image: alpine\n    environment:\n      LITERAL: $$VAR\n      LITERAL_BRACED: $${notavar}\n      MIXED: pre-$$HOME-post\n"
	in, err := ParseConfig(raw)
	if err != nil {
		t.Fatal(err)
	}
	m := map[string]string{}
	for _, se := range in.Container {
		if se.Service != "web" {
			continue
		}
		for _, v := range se.Vars {
			if v.State == containerenv.StateSet {
				m[v.Key] = v.Value
			}
		}
	}
	if m["LITERAL"] != "$VAR" {
		t.Fatalf("LITERAL %q %+v", m["LITERAL"], m)
	}
	if m["LITERAL_BRACED"] != "${notavar}" {
		t.Fatalf("LITERAL_BRACED %q", m["LITERAL_BRACED"])
	}
	if m["MIXED"] != "pre-$HOME-post" {
		t.Fatalf("MIXED %q", m["MIXED"])
	}
}

func TestCompareEscapedLiteralMatch(t *testing.T) {
	in := explain.Input{
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
		Container: []containerenv.ServiceEnv{{
			Service: "web",
			Vars: []containerenv.Variable{
				{Service: "web", Key: "LITERAL", Value: "$VAR", State: containerenv.StateSet},
			},
		}},
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    environment:\n      LITERAL: $$VAR\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "web:LITERAL")
	if row.State != StateMatch || row.Internal != "$VAR" || row.Engine != "$VAR" {
		t.Fatalf("%+v", row)
	}
}

func mustRow(t *testing.T, rep Report, path string) Row {
	t.Helper()
	for _, r := range rep.Rows {
		if r.Path == path {
			return r
		}
	}
	t.Fatalf("missing path %s in %+v", path, rep.Rows)
	return Row{}
}
