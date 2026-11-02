// SPDX-License-Identifier: Apache-2.0

package check

import (
	"testing"

	"composelens/internal/policy"
)

func TestApplyPolicyDisableSeverityAndWaiver(t *testing.T) {
	shadow := Evaluate(fixture(t, "env-shadowing"))
	if !hasID(shadow, CHK05) {
		t.Fatalf("need CHK05 baseline %+v", shadow.Findings)
	}
	disabled, err := policy.Parse([]byte("schema: composelens.policy.v0\nrules:\n  - id: CHK05\n    enabled: false\n"))
	if err != nil {
		t.Fatal(err)
	}
	got := ApplyPolicy(shadow, disabled)
	if hasID(got, CHK05) {
		t.Fatalf("CHK05 should be disabled %+v", got.Findings)
	}

	secret := Evaluate(fixture(t, "secret-inline"))
	if !hasID(secret, CHK01) {
		t.Fatal("need CHK01")
	}
	sev, err := policy.Parse([]byte("schema: composelens.policy.v0\nrules:\n  - id: CHK01\n    severity: error\n"))
	if err != nil {
		t.Fatal(err)
	}
	got = ApplyPolicy(secret, sev)
	found := false
	for _, f := range got.Findings {
		if f.ID == CHK01 {
			found = true
			if f.Severity != SevError {
				t.Fatalf("severity %s", f.Severity)
			}
		}
	}
	if !found {
		t.Fatal("CHK01 missing after severity overlay")
	}

	dep := Evaluate(fixture(t, "profiled-dep"))
	if !hasID(dep, CHK03) {
		t.Fatal("need CHK03")
	}
	waive, err := policy.Parse([]byte("schema: composelens.policy.v0\nexceptions:\n  - rule: CHK03\n    expires: \"2099-12-31\"\n"))
	if err != nil {
		t.Fatal(err)
	}
	got = ApplyPolicy(dep, waive)
	found = false
	for _, f := range got.Findings {
		if f.ID == CHK03 {
			found = true
			if !f.Waived || f.WaiverExpires != "2099-12-31" {
				t.Fatalf("CHK03 must stay visible as waived: %+v", f)
			}
		}
	}
	if !found {
		t.Fatal("waived CHK03 was silently dropped")
	}
	if AssertionExit(got) != 0 {
		t.Fatalf("waived warning must not gate, exit %d", AssertionExit(got))
	}
}

func TestApplyPolicyNilUnchanged(t *testing.T) {
	in := Evaluate(fixture(t, "env-shadowing"))
	got := ApplyPolicy(in, nil)
	if len(got.Findings) != len(in.Findings) || got.PolicySchema != "" {
		t.Fatalf("%+v vs %+v", got, in)
	}
}
