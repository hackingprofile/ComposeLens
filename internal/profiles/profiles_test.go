// SPDX-License-Identifier: Apache-2.0

package profiles

import (
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/merge"
	"composelens/internal/redact"
)

func docsFrom(t *testing.T, pairs ...string) []*composeparse.Document {
	t.Helper()
	var out []*composeparse.Document
	for i := 0; i+1 < len(pairs); i += 2 {
		d, err := composeparse.Parse(discover.File{Path: pairs[i], Bytes: []byte(pairs[i+1]), Origin: "fixture"})
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, d)
	}
	return out
}

func merged(t *testing.T, yaml string) []merge.Field {
	t.Helper()
	return merge.Documents(docsFrom(t, "compose.yaml", yaml), nil)
}

func byName(svcs []Service) map[string]Service {
	m := map[string]Service{}
	for _, s := range svcs {
		m[s.Name] = s
	}
	return m
}

func TestAlwaysOnWithoutProfiles(t *testing.T) {
	svcs := Activate(merged(t, "services:\n  web:\n    image: nginx\n"), nil)
	web := byName(svcs)["web"]
	if web.State != StateEnabled || web.Reason != ReasonAlwaysOn || web.Certainty != "proven" {
		t.Fatalf("%+v", web)
	}
}

func TestDottedAndCollisionServiceNames(t *testing.T) {
	svcs := Activate(merged(t, "services:\n  web.api:\n    image: nginx\n"), nil)
	if len(svcs) != 1 || svcs[0].Name != "web.api" {
		t.Fatalf("%+v", svcs)
	}
	both := Activate(merged(t, "services:\n  web:\n    image: alpine\n  web.api:\n    image: nginx\n"), nil)
	m := byName(both)
	if m["web"].Name != "web" || m["web.api"].Name != "web.api" || len(m) != 2 {
		t.Fatalf("%+v", both)
	}
}

func TestEnableIfAnyActiveSingleAndMultiple(t *testing.T) {
	yaml := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"  debug:\n" +
		"    image: alpine\n" +
		"    profiles: [debug]\n" +
		"  worker:\n" +
		"    image: busybox\n" +
		"    profiles:\n" +
		"      - debug\n" +
		"      - tools\n"
	fields := merged(t, yaml)
	none := byName(Activate(fields, nil))
	if none["web"].State != StateEnabled || none["debug"].State != StateDisabled || none["worker"].State != StateDisabled {
		t.Fatalf("default %+v", none)
	}
	if !strings.Contains(none["debug"].Reason, "none of its profiles {debug}") {
		t.Fatalf("debug reason %s", none["debug"].Reason)
	}
	debug := byName(Activate(fields, Active([]string{"debug"}, nil)))
	if debug["debug"].State != StateEnabled || debug["debug"].Matched != "debug" || debug["debug"].MatchedSource != SourceFlag {
		t.Fatalf("debug %+v", debug["debug"])
	}
	if debug["worker"].State != StateEnabled || debug["worker"].Matched != "debug" {
		t.Fatalf("worker via debug %+v", debug["worker"])
	}
	tools := byName(Activate(fields, Active([]string{"tools"}, nil)))
	if tools["worker"].State != StateEnabled || tools["worker"].Matched != "tools" {
		t.Fatalf("worker via tools %+v", tools["worker"])
	}
	if tools["debug"].State != StateDisabled {
		t.Fatalf("debug still on %+v", tools["debug"])
	}
}

func TestActiveFromComposeProfilesEnv(t *testing.T) {
	act := Active(nil, []string{"COMPOSE_PROFILES=debug, tools"})
	if len(act) != 2 || act[0].Name != "debug" || act[0].Source != SourceEnv || act[1].Name != "tools" {
		t.Fatalf("%+v", act)
	}
}

func TestFlagsOverrideComposeProfiles(t *testing.T) {
	act := Active([]string{"tools"}, []string{"COMPOSE_PROFILES=debug"})
	if len(act) != 1 || act[0].Name != "tools" || act[0].Source != SourceFlag {
		t.Fatalf("%+v", act)
	}
}

func TestInactiveProfiledDependsOnIsNotProvenEnabled(t *testing.T) {
	yaml := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    depends_on:\n" +
		"      - db\n" +
		"  db:\n" +
		"    image: postgres\n" +
		"    profiles: [storage]\n"
	svcs := byName(Activate(merged(t, yaml), nil))
	if svcs["web"].State != StateEnabled || svcs["web"].Reason != ReasonAlwaysOn || svcs["web"].Certainty != "proven" {
		t.Fatalf("web %+v", svcs["web"])
	}
	db := svcs["db"]
	if db.State != StateDisabled {
		t.Fatalf("db must stay not-enabled-by-profiles %+v", db)
	}
	if db.Certainty != "unknown" || db.Evidence != "unsupported" {
		t.Fatalf("db certainty %+v", db)
	}
	if db.ImplicitOf != "web" {
		t.Fatalf("db implicitOf %+v", db)
	}
	if !strings.Contains(db.Reason, "required by web via depends_on") || !strings.Contains(db.Reason, "{storage}") {
		t.Fatalf("db reason %s", db.Reason)
	}
	if strings.Contains(db.Reason, "enabled implicitly") || strings.Contains(strings.ToLower(db.Reason), "documented compose") {
		t.Fatalf("over-claimed reason %s", db.Reason)
	}
}

func TestInactiveProfiledDependsOnMappingForm(t *testing.T) {
	yaml := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    depends_on:\n" +
		"      db:\n" +
		"        condition: service_started\n" +
		"  db:\n" +
		"    image: postgres\n" +
		"    profiles: [storage]\n"
	svcs := byName(Activate(merged(t, yaml), nil))
	if svcs["db"].State != StateDisabled || svcs["db"].Certainty != "unknown" || svcs["db"].ImplicitOf != "web" {
		t.Fatalf("db %+v", svcs["db"])
	}
}

func TestDependsOnTargetEnabledByOwnProfileUnchanged(t *testing.T) {
	yaml := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    depends_on: [db]\n" +
		"  db:\n" +
		"    image: postgres\n" +
		"    profiles: [storage]\n"
	svcs := byName(Activate(merged(t, yaml), Active([]string{"storage"}, nil)))
	if svcs["db"].State != StateEnabled || svcs["db"].Matched != "storage" || svcs["db"].Certainty != "proven" {
		t.Fatalf("db %+v", svcs["db"])
	}
	if svcs["db"].ImplicitOf != "" || strings.Contains(svcs["db"].Reason, "depends_on") {
		t.Fatalf("own-profile path must not become advisory %+v", svcs["db"])
	}
}

func TestDependsOnUnprofiledTargetAlwaysOnUnchanged(t *testing.T) {
	yaml := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    depends_on: [db]\n" +
		"  db:\n" +
		"    image: postgres\n"
	svcs := byName(Activate(merged(t, yaml), nil))
	if svcs["db"].State != StateEnabled || svcs["db"].Reason != ReasonAlwaysOn || svcs["db"].Certainty != "proven" {
		t.Fatalf("db %+v", svcs["db"])
	}
}

func TestTransitiveInactiveProfiledDependsOnNotWalkedAsEnabled(t *testing.T) {
	yaml := "" +
		"services:\n" +
		"  web:\n" +
		"    image: nginx\n" +
		"    depends_on: [api]\n" +
		"  api:\n" +
		"    image: api\n" +
		"    profiles: [backend]\n" +
		"    depends_on: [db]\n" +
		"  db:\n" +
		"    image: postgres\n" +
		"    profiles: [storage]\n"
	svcs := byName(Activate(merged(t, yaml), nil))
	if svcs["api"].State != StateDisabled || svcs["api"].Certainty != "unknown" || svcs["api"].ImplicitOf != "web" {
		t.Fatalf("api %+v", svcs["api"])
	}
	if svcs["db"].State != StateDisabled || svcs["db"].Certainty != "proven" {
		t.Fatalf("db should remain ordinary disabled, not implicit-enabled %+v", svcs["db"])
	}
	if svcs["db"].ImplicitOf != "" {
		t.Fatalf("db must not inherit a requires-edge from a not-enabled api %+v", svcs["db"])
	}
}

func TestMappingProfilesUnsupported(t *testing.T) {
	yaml := "services:\n  odd:\n    image: alpine\n    profiles:\n      debug: true\n"
	svcs := byName(Activate(merged(t, yaml), Active([]string{"debug"}, nil)))
	if svcs["odd"].State != StateUnsupported || svcs["odd"].Certainty != "unknown" {
		t.Fatalf("%+v", svcs["odd"])
	}
}

func TestSecretProfileNameFragments(t *testing.T) {
	secret := "ghp_ComposeLensProfileProbe99"
	act := Active([]string{secret}, nil)
	if len(act) != 1 || !act[0].Secret {
		t.Fatalf("%+v", act)
	}
	frags := SecretFragments(act, nil)
	found := false
	for _, f := range frags {
		if strings.Contains(f, secret) {
			found = true
		}
	}
	if !found {
		t.Fatalf("fragments %v", frags)
	}
	if !redact.LooksLikeSecret(secret) {
		t.Fatal("classifier missed probe token")
	}
}
