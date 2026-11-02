// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"composelens/internal/evidence"
	"composelens/internal/testenv"
)

func explainEffective(t *testing.T, dir string, environ []string, target string) (string, string) {
	t.Helper()
	code, out, errs := runIn(t, dir, environ, "explain", "--json", target)
	if code != 0 {
		t.Fatalf("explain %s: exit %d %s", target, code, errs)
	}
	var rep explainReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatal(err)
	}
	text := ""
	if rep.Effective.Text != nil {
		text = *rep.Effective.Text
	}
	return text, rep.Certainty
}

// Expected values are what docker compose config (v5.4.0) produces for the
// same files; the engine prints "$" as "$$" in its own output.
func TestNestedDefaultsResolveAsTheEngineDoes(t *testing.T) {
	dir := writeProject(t, map[string]string{
		".env": "B=bee\n",
		"compose.yaml": "services:\n  t:\n    image: alpine\n    environment:\n" +
			"      C12: \"${UNSET:-${B}}\"\n" +
			"      C20: \"${UNSET-${B:-c}}\"\n" +
			"      DEEP: \"${U1:-${U2:-${B}}}\"\n" +
			"      ALT: \"${B:+x${B}}\"\n" +
			"      ESC: \"${UNSET:-$${B}}\"\n" +
			"      TAIL: \"${UNSET:-a}b}\"\n",
	})
	want := map[string]string{"C12": "bee", "C20": "bee", "DEEP": "bee", "ALT": "xbee", "ESC": "${B}", "TAIL": "ab}"}
	for key, w := range want {
		got, cert := explainEffective(t, dir, nil, "t:"+key)
		if got != w || cert != evidence.Proven {
			t.Errorf("t:%s = %q (%s), want %q (proven)", key, got, cert, w)
		}
	}
}

func TestEnvFileValuesExpandAsTheEngineDoes(t *testing.T) {
	dir := writeProject(t, map[string]string{
		".env":  "B=bee\nEXP=${B}-x\nDOLLAR_LIT=a$$b\nSQ='${B}'\nFWD=${LATER}\nLATER=late\n",
		"a.env": "A=from_a\nIP=${A}\nFB=${B}\nFD=x$$y\nFQ='q$$q'\n",
		"compose.yaml": "services:\n  t:\n    image: alpine\n    env_file: a.env\n    environment:\n" +
			"      C27: \"${EXP}\"\n      C32: \"${DOLLAR_LIT}\"\n      SQ: \"${SQ}\"\n      FWD: \"${FWD}\"\n",
	})
	want := map[string]string{
		"C27": "bee-x", "C32": "a$b", "SQ": "${B}", "FWD": "",
		"IP": "from_a", "FB": "bee", "FD": "x$y", "FQ": "q$$q",
	}
	for key, w := range want {
		got, _ := explainEffective(t, dir, nil, "t:"+key)
		if got != w {
			t.Errorf("t:%s = %q, want %q", key, got, w)
		}
	}
	// The process environment wins over earlier entries of the file.
	got, _ := explainEffective(t, dir, []string{"B=from_os", "A=os_a"}, "t:C27")
	if got != "from_os-x" {
		t.Errorf("t:C27 with B in the environment = %q, want from_os-x", got)
	}
	got, _ = explainEffective(t, dir, []string{"A=os_a"}, "t:IP")
	if got != "os_a" {
		t.Errorf("t:IP with A in the environment = %q, want os_a", got)
	}
}

func TestProfileWildcardEnablesEveryProfile(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  web: {image: nginx}\n  dbg: {image: busybox, profiles: [debug]}\n",
	})
	for name, run := range map[string]func() string{
		"flag": func() string { _, out, _ := runIn(t, dir, nil, "inspect", "--profile", "*"); return out },
		"env":  func() string { _, out, _ := runIn(t, dir, []string{"COMPOSE_PROFILES=*"}, "inspect"); return out },
	} {
		out := run()
		if !strings.Contains(out, "dbg  enabled") {
			t.Errorf("%s: profile * should enable dbg:\n%s", name, out)
		}
	}
}

func TestMultiDocumentFileMergesAsTheEngineDoes(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  w:\n    image: nginx\n    environment: {A: one}\n---\n" +
			"services:\n  w:\n    environment: {A: two, B: b}\n  x:\n    image: y\n",
	})
	for target, w := range map[string]string{"w:A": "two", "w:B": "b", "services.x.image": "y", "services.w.image": "nginx"} {
		got, _ := explainEffective(t, dir, nil, target)
		if got != w {
			t.Errorf("%s = %q, want %q", target, got, w)
		}
	}
}

func TestEngineRejectedFormsAreNotProven(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  w:\n    image: nginx\n    environment: {S: \"${A:0:2}\", E: \"${}\", N: \"${1A}\"}\n",
	})
	for _, key := range []string{"S", "E", "N"} {
		_, out, _ := runIn(t, dir, nil, "inspect")
		if !strings.Contains(out, "invalid-format") {
			t.Fatalf("invalid interpolation not reported:\n%s", out)
		}
		if _, cert := explainEffective(t, dir, nil, "w:"+key); cert == evidence.Proven {
			t.Errorf("w:%s is proven, but Compose rejects the file", key)
		}
	}
	inc := writeProject(t, map[string]string{
		"compose.yaml": "include: other.yaml\nservices:\n  w:\n    image: nginx\n",
		"other.yaml":   "services: {o: {image: x}}\n",
	})
	_, out, _ := runIn(t, inc, nil, "inspect")
	if !strings.Contains(out, "Compose requires include: to be a list") {
		t.Errorf("a scalar include must say that Compose rejects it:\n%s", out)
	}
	if _, cert := explainEffective(t, inc, nil, "services.o.image"); cert == evidence.Proven {
		t.Errorf("a value from a scalar include is proven, but Compose rejects the file")
	}
}

// TestLiveInterpolationAgreesWithEngine runs the same project through
// docker compose config and requires every modelled row to match.
func TestLiveInterpolationAgreesWithEngine(t *testing.T) {
	testenv.RequireDocker(t)
	dir := writeProject(t, map[string]string{
		".env":  "B=bee\nEXP=${B}-x\nDOLLAR_LIT=a$$b\n",
		"a.env": "A=from_a\nIP=${A}\n",
		"compose.yaml": "services:\n  t:\n    image: alpine\n    env_file: a.env\n    environment:\n" +
			"      C12: \"${UNSET:-${B}}\"\n      C20: \"${UNSET-${B:-c}}\"\n      C27: \"${EXP}\"\n      C32: \"${DOLLAR_LIT}\"\n",
	})
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: dir}
	if code := rt.Run([]string{"differential", "--json"}); code != 0 {
		t.Fatalf("differential exit %d: %s", code, errb.String())
	}
	var rep struct {
		Rows []struct {
			Path  string `json:"path"`
			State string `json:"state"`
		} `json:"rows"`
	}
	if err := json.Unmarshal(out.Bytes(), &rep); err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for _, r := range rep.Rows {
		seen[r.Path] = r.State
		if r.State == "divergent" {
			t.Errorf("divergent row %s", r.Path)
		}
	}
	for _, p := range []string{"t:C12", "t:C20", "t:C27", "t:C32", "t:IP"} {
		if seen[p] != "match" {
			t.Errorf("row %s is %q, want match", p, seen[p])
		}
	}
}
