// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Regression tests: a shadowed or overridden secret explains withheld instead
// of failing closed, and a displayed non-secret value is not guard material.

func writeProbeProject(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A secret-keyed container variable whose env_file loser differs from the
// environment winner must explain with the loser withheld, not fail closed.
func TestExplainShadowedSecretLoserIsWithheldNotRefused(t *testing.T) {
	loser := "firstsecretvalue"
	winner := "secondsecretvalue"
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine\n    env_file: .env.app\n    environment:\n      PASSWORD: " + winner + "\n",
		".env.app":     "PASSWORD=" + loser + "\n",
	})
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"explain", "--json", "web:PASSWORD", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("explain --json code=%d err=%s", code, errb.String())
	}
	blob := out.String() + errb.String()
	if strings.Contains(blob, loser) || strings.Contains(blob, winner) {
		t.Fatal("raw secret leaked in explain --json")
	}
	var rep explainReport
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	if !rep.Secret || !rep.Effective.Redacted {
		t.Fatalf("effective must be withheld: %+v", rep.Effective)
	}
	found := false
	for _, st := range rep.Stages {
		if st.Name != "container-environment" {
			continue
		}
		found = true
		if !st.Secret || len(st.Overridden) != 1 {
			t.Fatalf("container stage %+v", st)
		}
		line := st.Overridden[0]
		if !strings.HasPrefix(line, "env-file ") || !strings.HasSuffix(line, " [redacted]") {
			t.Fatalf("loser must keep its source label and withhold the value: %q", line)
		}
		if !strings.Contains(line, ".env.app") {
			t.Fatalf("loser must name the env file: %q", line)
		}
	}
	if !found {
		t.Fatalf("no container-environment stage: %+v", rep.Stages)
	}

	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"explain", "web:PASSWORD", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("human code=%d err=%s", code, errb.String())
	}
	human := out.String() + errb.String()
	if strings.Contains(human, loser) || strings.Contains(human, winner) {
		t.Fatal("raw secret leaked in human explain")
	}
	if !strings.Contains(human, "overridden: env-file ") || !strings.Contains(human, " [redacted]") {
		t.Fatalf("human loser line missing or unredacted:\n%s", human)
	}
}

// The same contract for a secret-keyed field overridden across files.
func TestExplainMergeOverriddenSecretIsWithheldNotRefused(t *testing.T) {
	base := "basefilesecretvalue"
	over := "overridefilesecretvalue"
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml":          "services:\n  web:\n    image: alpine\n    environment:\n      DB_PASSWORD: " + base + "\n",
		"compose.override.yaml": "services:\n  web:\n    environment:\n      DB_PASSWORD: " + over + "\n",
	})
	rt, out, errb := reportRT(dir)
	for _, target := range []string{"services.web.environment.DB_PASSWORD", "web:DB_PASSWORD"} {
		out.Reset()
		errb.Reset()
		code := rt.Run([]string{"explain", "--json", target, "--project-directory", dir})
		if code != 0 {
			t.Fatalf("%s code=%d err=%s", target, code, errb.String())
		}
		blob := out.String() + errb.String()
		if strings.Contains(blob, base) || strings.Contains(blob, over) {
			t.Fatalf("%s leaked a merge value", target)
		}
		var rep explainReport
		if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
			t.Fatal(err)
		}
		merged := false
		for _, st := range rep.Stages {
			if st.Name != "merge" {
				continue
			}
			merged = true
			if !st.Secret || len(st.Overridden) != 1 || !strings.HasSuffix(st.Overridden[0], " [redacted]") || !strings.Contains(st.Overridden[0], "compose.yaml") {
				t.Fatalf("%s merge stage %+v", target, st)
			}
		}
		if !merged {
			t.Fatalf("%s has no merge stage: %+v", target, rep.Stages)
		}
	}
}

func TestSyntheticMarkerValueIsNotGuardMaterial(t *testing.T) {
	image := "registry.example.test/synthetic-data:1.0"
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: " + image + "\n    environment:\n      APP_ENV: production\n",
	})
	rt, out, errb := reportRT(dir)
	for _, args := range [][]string{
		{"explain", "--all", "--json", "--project-directory", dir},
		{"explain", "--all", "--project-directory", dir},
		{"report", "--json", "--project-directory", dir},
	} {
		out.Reset()
		errb.Reset()
		if code := rt.Run(args); code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		if !strings.Contains(out.String(), image) {
			t.Fatalf("%v must display the non-secret image value", args)
		}
	}
}
