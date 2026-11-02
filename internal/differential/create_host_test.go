// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"testing"

	"composelens/internal/engineadapter"
)

// The short bind syntax implies create_host_path: true. Some engine releases
// print that default in their long-form dump and others omit it; both are the
// same mount.
func TestShortBindMatchesEngineWithOrWithoutImpliedCreateHostPath(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: alpine\n    volumes:\n      - './rel:/data'\n")
	if err != nil {
		t.Fatal(err)
	}
	for name, bind := range map[string]string{
		"printed": "        bind:\n          create_host_path: true\n",
		"omitted": "",
	} {
		eng, err := ParseConfig("services:\n  web:\n    image: alpine\n    volumes:\n      - type: bind\n        source: ./rel\n        target: /data\n" + bind)
		if err != nil {
			t.Fatal(err)
		}
		rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
		if row := mustRow(t, rep, "services.web.volumes"); row.State != StateMatch {
			t.Errorf("%s: %+v", name, row)
		}
	}
	explicit, err := ParseConfig("services:\n  web:\n    image: alpine\n    volumes:\n      - type: bind\n        source: ./rel\n        target: /data\n        bind:\n          create_host_path: false\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, explicit, Meta{EngineState: engineadapter.StateCaptured})
	if row := mustRow(t, rep, "services.web.volumes"); row.State == StateMatch {
		t.Errorf("an explicit create_host_path: false is a different mount: %+v", row)
	}
}
