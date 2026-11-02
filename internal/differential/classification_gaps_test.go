// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"testing"

	"composelens/internal/engineadapter"
)

// Each internal/engine pair is what ComposeLens and docker compose config
// (v5.4.0) produce for the same source line; none is a real disagreement.
func TestEquivalentFormsAreNotUnexplainedDivergences(t *testing.T) {
	in, err := ParseConfig("services:\n  web:\n    image: nginx\n" +
		"    hostname: \"\"\n" +
		"    extra_hosts: []\n" +
		"    networks: [front]\n" +
		"    command: nginx -g \"daemon off;\"\n" +
		"    environment:\n      EMPTYV: \"\"\n" +
		"networks:\n  front: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	eng, err := ParseConfig("services:\n  web:\n    image: nginx\n" +
		"    networks:\n      front: null\n" +
		"    command: [\"nginx\", \"-g\", \"daemon off;\"]\n" +
		"    environment:\n      EMPTYV: \"\"\n" +
		"networks:\n  front: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	rep := CompareInputs(in, eng, Meta{EngineState: engineadapter.StateCaptured})
	for _, path := range []string{"services.web.hostname", "services.web.extra_hosts", "services.web.networks", "web:EMPTYV"} {
		for _, r := range rep.Rows {
			if r.Path == path && r.State != StateMatch {
				t.Errorf("%s: %s internal=%q engine=%q, want match", path, r.State, r.Internal, r.Engine)
			}
		}
	}
	cmd := mustRow(t, rep, "services.web.command")
	if cmd.State == StateDivergent && cmd.Detail != DetailD2ShellVsExec {
		t.Errorf("shell-form command with quotes lacks the D2 label: %+v", cmd)
	}
	env := mustRow(t, rep, "web:EMPTYV")
	if env.State != StateMatch {
		t.Errorf("an empty string set on both sides must match: %+v", env)
	}
}
