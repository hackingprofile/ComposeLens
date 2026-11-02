// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"testing"

	"composelens/internal/differential"
)

// The catalog records which engine version its values came from; a run
// against another Compose release is compared row by row, not refused.
func TestCorpusAcceptsTheEngineVersionPresent(t *testing.T) {
	fx := Fixture{ID: "probe", Expected: Expected{Engine: EngineMatched, EnginePin: "v5.4.0"}}
	for _, have := range []string{"v5.4.0", "v5.6.1", "v2.40.3"} {
		row := CorpusRow{LiveVersion: have, InScope: []differential.Row{{Path: "services.web.image", State: differential.StateMatch}}}
		if err := checkCorpusExpect(fx, row); err != nil {
			t.Errorf("engine %s: %v", have, err)
		}
	}
	row := CorpusRow{LiveVersion: "v5.6.1", InScope: []differential.Row{{Path: "services.web.image", State: differential.StateDivergent}}}
	if err := checkCorpusExpect(fx, row); err == nil {
		t.Error("a divergent row must still fail, whatever the engine version")
	}
}
