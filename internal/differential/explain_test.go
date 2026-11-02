// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"testing"

	"composelens/internal/containerenv"
	"composelens/internal/engineadapter"
	"composelens/internal/explain"
	"composelens/internal/profiles"
)

func TestExplainD1BindSourceAsWritten(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n    volumes:\n      - \"./rel:/in\"\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    volumes:\n      - type: bind\n        source: /abs/project/rel\n        target: /in\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.volumes")
	if row.State != StateDivergent {
		t.Fatalf("want divergent %+v", row)
	}
	if row.Classification != ClassByDesign || row.Detail != DetailD1BindAsWritten {
		t.Fatalf("D1 must be explained/by-design %+v", row)
	}
}

func TestExplainD2ShellVsExecDump(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n    command: echo ok\n    entrypoint: echo entry\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    command: [\"echo\", \"ok\"]\n    entrypoint: [\"echo\", \"entry\"]\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	cmd := mustRow(t, rep, "services.web.command")
	if cmd.State != StateDivergent || cmd.Classification != ClassByDesign || cmd.Detail != DetailD2ShellVsExec {
		t.Fatalf("D2 command %+v", cmd)
	}
	ep := mustRow(t, rep, "services.web.entrypoint")
	if ep.State != StateDivergent || ep.Classification != ClassByDesign || ep.Detail != DetailD2ShellVsExec {
		t.Fatalf("D2 entrypoint %+v", ep)
	}
}

func TestExplainD4NestedDefault(t *testing.T) {
	in := explain.Input{
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
		Container: []containerenv.ServiceEnv{{
			Service: "web",
			Vars: []containerenv.Variable{
				{Service: "web", Key: "NESTED", Value: "$OTHER", State: containerenv.StateSet},
			},
		}},
	}
	eng := explain.Input{
		Profiles: []profiles.Service{{Name: "web", State: profiles.StateEnabled}},
		Container: []containerenv.ServiceEnv{{
			Service: "web",
			Vars: []containerenv.Variable{
				{Service: "web", Key: "NESTED", Value: "other-value", State: containerenv.StateSet},
			},
		}},
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "web:NESTED")
	if row.State != StateDivergent || row.Classification != ClassKnownLimitation || row.Detail != DetailD4NestedDefault {
		t.Fatalf("D4 %+v", row)
	}
}

func TestExplainD3DefaultNetworks(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    networks:\n      default: null\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.networks")
	if row.State != StateOnlyEngine || row.Classification != ClassByDesign || row.Detail != DetailD3DefaultNetwork {
		t.Fatalf("D3 %+v", row)
	}
}

func TestExplainD3CustomNetworkStaysBare(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    networks:\n      frontend: null\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.networks")
	if row.State != StateOnlyEngine {
		t.Fatalf("want only-engine %+v", row)
	}
	if row.Classification != "" || row.Detail != "" {
		t.Fatalf("custom network only-engine must stay unexplained %+v", row)
	}
}

func TestExplainD3ExtraDefaultWithDeclaredNetwork(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n    networks:\n      frontend: null\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    networks:\n      default: null\n      frontend: null\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.networks")
	if row.State != StateDivergent || row.Classification != ClassByDesign || row.Detail != DetailD3DefaultNetwork {
		t.Fatalf("D3 extra default %+v", row)
	}
}

func TestRepresentativeZeroUnexplainedD1D2D3D4(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n    command: echo ok\n    volumes:\n      - \"./rel:/in\"\n")
	if err != nil {
		t.Fatal(err)
	}
	in.Container = []containerenv.ServiceEnv{{
		Service: "web",
		Vars: []containerenv.Variable{
			{Service: "web", Key: "NESTED", Value: "$OTHER", State: containerenv.StateSet},
		},
	}}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    command: [\"echo\", \"ok\"]\n    volumes:\n      - type: bind\n        source: /abs/project/rel\n        target: /in\n    networks:\n      default: null\n")
	if err != nil {
		t.Fatal(err)
	}
	eng.Container = []containerenv.ServiceEnv{{
		Service: "web",
		Vars: []containerenv.Variable{
			{Service: "web", Key: "NESTED", Value: "other-value", State: containerenv.StateSet},
		},
	}}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	d1 := mustRow(t, rep, "services.web.volumes")
	d2 := mustRow(t, rep, "services.web.command")
	d3 := mustRow(t, rep, "services.web.networks")
	d4 := mustRow(t, rep, "web:NESTED")
	if d1.Classification != ClassByDesign || d1.Detail != DetailD1BindAsWritten {
		t.Fatalf("D1 %+v", d1)
	}
	if d2.Classification != ClassByDesign || d2.Detail != DetailD2ShellVsExec {
		t.Fatalf("D2 %+v", d2)
	}
	if d3.Classification != ClassByDesign || d3.Detail != DetailD3DefaultNetwork {
		t.Fatalf("D3 %+v", d3)
	}
	if d4.Classification != ClassKnownLimitation || d4.Detail != DetailD4NestedDefault {
		t.Fatalf("D4 %+v", d4)
	}
	for _, row := range rep.Rows {
		if row.State == StateMatch || row.State == StateUncertain {
			continue
		}
		if row.Classification == "" {
			t.Fatalf("unexplained row %+v", row)
		}
	}
}

func TestUnexplainedImageDivergenceStaysBare(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: nginx\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: alpine\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	row := mustRow(t, rep, "services.web.image")
	if row.State != StateDivergent {
		t.Fatalf("%+v", row)
	}
	if row.Classification != "" || row.Detail != "" {
		t.Fatalf("unrelated divergence must stay unexplained %+v", row)
	}
}
