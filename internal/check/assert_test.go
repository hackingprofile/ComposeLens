// SPDX-License-Identifier: Apache-2.0

package check

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"composelens/internal/exitcode"
	"composelens/internal/policy"
)

func TestAssertionExitDefaultErrorGate(t *testing.T) {
	warn := Evaluate(fixture(t, "secret-inline"))
	if AssertionExit(warn) != exitcode.OK {
		t.Fatalf("warning must not gate: %d", AssertionExit(warn))
	}
	info := Evaluate(fixture(t, "env-shadowing"))
	if AssertionExit(info) != exitcode.OK {
		t.Fatalf("info must not gate: %d", AssertionExit(info))
	}
	err := Evaluate(fixture(t, "required-unset"))
	if AssertionExit(err) != exitcode.Assertion {
		t.Fatalf("error must gate: %d", AssertionExit(err))
	}
	clean := Evaluate(fixture(t, "clean"))
	if AssertionExit(clean) != exitcode.OK {
		t.Fatalf("clean must be 0: %d", AssertionExit(clean))
	}
}

func TestPolicyGateWarningFailsOnCHK01(t *testing.T) {
	secret := Evaluate(fixture(t, "secret-inline"))
	if AssertionExit(secret) != exitcode.OK {
		t.Fatal("default gate is error")
	}
	doc, err := policy.Parse([]byte("schema: composelens.policy.v0\ngate: warning\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := ApplyPolicy(secret, doc)
	if got.Gate != SevWarning {
		t.Fatalf("gate %s", got.Gate)
	}
	if AssertionExit(got) != exitcode.Assertion {
		t.Fatalf("warning gate must fail on CHK01: %d", AssertionExit(got))
	}
}

func TestUnknownGateRejected(t *testing.T) {
	_, err := policy.Parse([]byte("schema: composelens.policy.v0\ngate: fatal\n"))
	if err == nil {
		t.Fatal("expected invalid gate")
	}
	pe, ok := err.(*policy.Error)
	if !ok || pe.Kind != policy.KindInvalidRule {
		t.Fatalf("got %#v", err)
	}
}

func TestExpiryExecutionClockFlip(t *testing.T) {
	before := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	onDay := time.Date(2026, 9, 10, 0, 0, 0, 0, time.UTC)
	policy.SetNowUTC(func() time.Time { return before })
	t.Cleanup(func() { policy.SetNowUTC(nil) })

	body := "schema: composelens.policy.v0\nrules:\n  - id: CHK01\n    severity: error\nexceptions:\n  - rule: CHK01\n    expires: \"2026-09-10\"\n"
	doc, err := policy.Parse([]byte(body))
	if err != nil {
		t.Fatal(err)
	}
	secret := Evaluate(fixture(t, "secret-inline"))
	waived := ApplyPolicy(secret, doc)
	var w Finding
	for _, f := range waived.Findings {
		if f.ID == CHK01 {
			w = f
		}
	}
	if !w.Waived {
		t.Fatalf("before expiry must waive: %+v", waived.Findings)
	}
	if AssertionExit(waived) != exitcode.OK {
		t.Fatalf("waived error must not gate: %d", AssertionExit(waived))
	}

	js, err := JSON(waived)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(js), `"waived": true`) {
		t.Fatalf("json waived marker: %s", js)
	}
	human := Human(waived)
	if !strings.Contains(human, "waived until 2026-09-10") {
		t.Fatalf("human waived: %s", human)
	}
	sarif, err := SARIF(waived)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSARIF(sarif); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(sarif), `"suppressions"`) || !strings.Contains(string(sarif), `"kind": "external"`) {
		t.Fatalf("sarif suppressions: %s", sarif)
	}
	if !strings.Contains(string(sarif), `"physicalLocation"`) {
		t.Fatalf("physical location missing: %s", sarif)
	}
	hf := FingerprintsFromHuman(human)
	jf, err := FingerprintsFromJSON(js)
	if err != nil {
		t.Fatal(err)
	}
	sf, err := FingerprintsFromSARIF(sarif)
	if err != nil {
		t.Fatal(err)
	}
	want := Fingerprints(waived)
	if strings.Join(hf, ",") != strings.Join(want, ",") || strings.Join(jf, ",") != strings.Join(want, ",") || strings.Join(sf, ",") != strings.Join(want, ",") {
		t.Fatalf("formats disagree\nh=%v\nj=%v\ns=%v\nw=%v", hf, jf, sf, want)
	}

	policy.SetNowUTC(func() time.Time { return onDay })
	returned := ApplyPolicy(secret, doc)
	var r Finding
	for _, f := range returned.Findings {
		if f.ID == CHK01 {
			r = f
		}
	}
	if r.Waived {
		t.Fatal("at expiry the waiver must not apply")
	}
	if AssertionExit(returned) != exitcode.Assertion {
		t.Fatalf("expired waiver must gate: %d", AssertionExit(returned))
	}
}

func TestLoadTimePastExpiryStillRejected(t *testing.T) {
	policy.SetNowUTC(func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) })
	t.Cleanup(func() { policy.SetNowUTC(nil) })
	_, err := policy.Parse([]byte("schema: composelens.policy.v0\nexceptions:\n  - rule: CHK01\n    expires: \"2026-09-03\"\n"))
	if err == nil {
		t.Fatal("expires on today must fail load")
	}
	pe, ok := err.(*policy.Error)
	if !ok || pe.Kind != policy.KindExceptionDate {
		t.Fatalf("got %#v", err)
	}
}

func TestWaivedJSONCounts(t *testing.T) {
	policy.SetNowUTC(func() time.Time { return time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC) })
	t.Cleanup(func() { policy.SetNowUTC(nil) })
	doc, err := policy.Parse([]byte("schema: composelens.policy.v0\nexceptions:\n  - rule: CHK03\n    expires: \"2099-12-31\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := ApplyPolicy(Evaluate(fixture(t, "profiled-dep")), doc)
	rep := NewReport(got)
	if rep.Counts.Waived != 1 || rep.Counts.Warning != 0 || AssertionExit(got) != 0 {
		t.Fatalf("%+v exit=%d", rep.Counts, AssertionExit(got))
	}
	raw, err := json.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"waived":true`) {
		t.Fatalf("%s", raw)
	}
}
