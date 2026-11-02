// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package fixtax

import (
	"testing"

	"composelens/internal/differential"
)

// On Linux and macOS the engine joins the project directory with "/" and
// keeps a backslash as a file-name character: "./rel" becomes {project}/rel
// and ".\rel" becomes {project}/.\rel. The catalog rows must match both.
func TestEngineFieldsUseThePlatformSeparator(t *testing.T) {
	project := "/work/fixtures/platform/x"
	cases := []struct {
		pe     PathExpect
		engine string
	}{
		{PathExpect{Path: "services.web.volumes", Value: `type=bind source={project}{sep}rel target=/in`},
			"type=bind source=/work/fixtures/platform/x/rel target=/in"},
		{PathExpect{Path: "services.web.volumes",
			Value:      `type=bind source={project}\rel target=/in{optional: create_host_path=true}`,
			PosixValue: `type=bind source={project}/.\rel target=/in{optional: create_host_path=true}`},
			`type=bind source=/work/fixtures/platform/x/.\rel target=/in`},
	}
	for _, c := range cases {
		fx := Fixture{Expected: Expected{EngineFields: []PathExpect{c.pe}}}
		row := CorpusRow{Project: project, InScope: []differential.Row{{Path: "services.web.volumes", Engine: c.engine}}}
		if err := matchEngineFields(fx, row); err != nil {
			t.Error(err)
		}
	}
	// A literal backslash is never turned into a separator.
	fx := Fixture{Expected: Expected{EngineFields: []PathExpect{{Path: "services.web.volumes", Value: `type=bind source={project}\rel target=/in`}}}}
	row := CorpusRow{Project: project, InScope: []differential.Row{{Path: "services.web.volumes", Engine: "type=bind source=/work/fixtures/platform/x/rel target=/in"}}}
	if err := matchEngineFields(fx, row); err == nil {
		t.Error(`{project}\rel matched {project}/rel: a backslash was rewritten`)
	}
}
