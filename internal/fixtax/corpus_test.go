// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"strings"
	"testing"

	"composelens/internal/differential"
)

func TestCheckCorpusExpectFailsWhenMatchedDiverges(t *testing.T) {
	fx := Fixture{
		ID: "interpolation.regression.escape",
		Expected: Expected{
			Engine:    EngineMatched,
			EnginePin: "v5.4.0",
			EngineFields: []PathExpect{
				{Path: "web:LITERAL", Value: "$VAR"},
			},
		},
	}
	row := CorpusRow{
		LiveVersion: "v5.4.0",
		InScope: []differential.Row{{
			Kind:     differential.KindEnv,
			Path:     "web:LITERAL",
			State:    differential.StateOnlyEngine,
			Internal: "",
			Engine:   "$VAR",
		}},
	}
	err := checkCorpusExpect(fx, row)
	if err == nil || !strings.Contains(err.Error(), "want match") {
		t.Fatalf("escape guard must fail on only-engine, got %v", err)
	}
}

func TestCheckCorpusExpectFailsWhenPortsReplaced(t *testing.T) {
	fx := Fixture{
		ID: "merge.regression.ports-append-dedup",
		Expected: Expected{
			Engine:    EngineMatched,
			EnginePin: "v5.4.0",
			EngineFields: []PathExpect{
				{Path: "services.web.ports", Value: "published=8080 target=80 protocol=tcp mode=ingress; published=9090 target=80 protocol=tcp mode=ingress; published=9191 target=90 protocol=tcp mode=ingress"},
			},
		},
	}
	row := CorpusRow{
		LiveVersion: "v5.4.0",
		InScope: []differential.Row{{
			Kind:     differential.KindField,
			Path:     "services.web.ports",
			State:    differential.StateDivergent,
			Internal: "published=9191 target=90 protocol=tcp mode=ingress",
			Engine:   "published=8080 target=80 protocol=tcp mode=ingress; published=9090 target=80 protocol=tcp mode=ingress; published=9191 target=90 protocol=tcp mode=ingress",
		}},
	}
	err := checkCorpusExpect(fx, row)
	if err == nil {
		t.Fatal("ports append guard must fail if ComposeLens replaced instead of appended")
	}
}
