// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

func TestCheckFailsOnMissingProjectDirectory(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "does-not-exist")
	for _, cmd := range []string{"check", "inspect", "report"} {
		args := []string{cmd, "--project-directory", missing}
		if cmd == "report" {
			args = append(args, "--json", "--no-engine")
		}
		code, _, errs := runIn(t, t.TempDir(), nil, args...)
		if code != exitcode.Input || !strings.Contains(errs, "project-directory-missing") {
			t.Errorf("%s: exit %d stderr=%s, want exit 3 project-directory-missing", cmd, code, errs)
		}
	}
}

func TestCheckFailsOnProjectWithoutComposeFile(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := runIn(t, dir, nil, "check")
	if code != exitcode.Input || !strings.Contains(errs, "no-compose-file") {
		t.Errorf("exit %d stderr=%s, want exit 3 no-compose-file", code, errs)
	}
}

func TestCheckReportsInputComposeRejects(t *testing.T) {
	cases := map[string]map[string]string{
		"top-level typo": {"compose.yaml": "servics:\n  w:\n    image: nginx\n"},
		"invalid interpolation": {"compose.yaml": "services:\n  w:\n    image: nginx\n" +
			"    environment: {S: \"${A:0:2}\"}\n"},
		"scalar include": {"compose.yaml": "include: other.yaml\nservices:\n  w:\n    image: nginx\n",
			"other.yaml": "services: {o: {image: x}}\n"},
		"include cycle": {"compose.yaml": "include: [a.yaml]\nservices:\n  w:\n    image: nginx\n",
			"a.yaml": "include: [b.yaml]\n", "b.yaml": "include: [a.yaml]\n"},
		"extends cycle": {"compose.yaml": "services:\n  a:\n    image: x\n    extends: {service: b}\n" +
			"  b:\n    extends: {service: a}\n"},
	}
	for name, files := range cases {
		dir := writeProject(t, files)
		code, out, errs := runIn(t, dir, nil, "check")
		if code != exitcode.Assertion || !strings.Contains(out, "CHK06") {
			t.Errorf("%s: exit %d, want %d with CHK06:\n%s%s", name, code, exitcode.Assertion, out, errs)
		}
	}
}

func TestCheckAcceptsEveryValidTopLevelKey(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "name: demo\nversion: \"3.9\"\ninclude: [other.yaml]\nx-common: {a: 1}\n" +
			"services:\n  w:\n    image: nginx\nnetworks: {n: {}}\nvolumes: {v: {}}\n" +
			"configs: {c: {file: ./c.txt}}\nsecrets: {s: {file: ./s.txt}}\nmodels: {m: {model: ai/x}}\n",
		"other.yaml": "services: {o: {image: x}}\n",
		"c.txt":      "c\n",
		"s.txt":      "s\n",
	})
	code, out, _ := runIn(t, dir, nil, "check")
	if strings.Contains(out, "CHK06") || code != exitcode.OK {
		t.Errorf("valid top-level keys reported: exit %d\n%s", code, out)
	}
}
