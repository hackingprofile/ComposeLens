// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/merge"
)

func loadProfileFixture(t *testing.T, name string) *composeparse.Document {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "profiles", name)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOfficialFixtureDefaultAndFlag(t *testing.T) {
	fields := merge.Documents([]*composeparse.Document{loadProfileFixture(t, "official.yaml")}, nil)
	none := byName(Activate(fields, nil))
	if none["web"].State != StateEnabled || none["debug"].State != StateDisabled || none["worker"].State != StateDisabled {
		t.Fatalf("%+v", none)
	}
	on := byName(Activate(fields, Active([]string{"debug"}, nil)))
	if on["debug"].State != StateEnabled || on["worker"].State != StateEnabled || on["debug"].MatchedSource != SourceFlag {
		t.Fatalf("%+v", on)
	}
}

func TestOfficialFixtureComposeProfilesEnv(t *testing.T) {
	fields := merge.Documents([]*composeparse.Document{loadProfileFixture(t, "official.yaml")}, nil)
	on := byName(Activate(fields, Active(nil, []string{"COMPOSE_PROFILES=tools"})))
	if on["worker"].State != StateEnabled || on["worker"].MatchedSource != SourceEnv {
		t.Fatalf("worker %+v", on["worker"])
	}
	if on["debug"].State != StateDisabled {
		t.Fatalf("debug %+v", on["debug"])
	}
}

func TestDependsFixtureInactiveProfiledIsNotProvenEnabled(t *testing.T) {
	fields := merge.Documents([]*composeparse.Document{loadProfileFixture(t, "depends.yaml")}, nil)
	svcs := byName(Activate(fields, nil))
	if svcs["db"].State != StateDisabled || svcs["db"].Certainty != "unknown" || svcs["db"].ImplicitOf != "web" {
		t.Fatalf("%+v", svcs["db"])
	}
}
