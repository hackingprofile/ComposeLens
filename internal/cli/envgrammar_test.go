// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
	"composelens/internal/testenv"
)

// containerVars runs inspect --json and returns service web's container
// environment (key -> value text; "<unset>" for a null text).
func containerVars(t *testing.T, dir string) (int, map[string]string, string) {
	t.Helper()
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"inspect", "--json", "--project-directory", dir})
	vars := map[string]string{}
	if code != exitcode.OK {
		return code, vars, errb.String()
	}
	var doc struct {
		ContainerEnvironment []struct {
			Service   string `json:"service"`
			Variables []struct {
				Key   string `json:"key"`
				Value struct {
					Text *string `json:"text"`
				} `json:"value"`
			} `json:"variables"`
		} `json:"containerEnvironment"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	for _, s := range doc.ContainerEnvironment {
		if s.Service != "web" {
			continue
		}
		for _, v := range s.Variables {
			if v.Value.Text == nil {
				vars[v.Key] = "<unset>"
			} else {
				vars[v.Key] = *v.Value.Text
			}
		}
	}
	return code, vars, errb.String()
}

const envProbeService = "services:\n  web:\n    image: alpine:3.21\n    env_file: app.env\n    environment:\n      FROM_PROJECT: ${COLOR}\n"

// Invalid UTF-8 in the project .env, a CLI --env-file or a service
// env_file is refused with invalid-encoding (exit 3) and empty stdout.
func TestInvalidUTF8EnvFilesRefuse(t *testing.T) {
	bad := "COLOR=green\xffvalue\n"
	colorSvc := "services:\n  web:\n    image: alpine:3.21\n    environment:\n      COLOR: ${COLOR}\n"
	cases := map[string]struct {
		files map[string]string
		extra []string
	}{
		"project .env":     {map[string]string{"compose.yaml": colorSvc, ".env": bad}, nil},
		"cli --env-file":   {map[string]string{"compose.yaml": colorSvc, "app.env": bad}, []string{"--env-file", "app.env"}},
		"service env_file": {map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    env_file: app.env\n", "app.env": bad}, nil},
	}
	for name, c := range cases {
		dir := writeProbeProject(t, c.files)
		rt, out, errb := reportRT(dir)
		code := rt.Run(append([]string{"inspect", "--json", "--project-directory", dir}, c.extra...))
		if code != exitcode.Input || out.Len() != 0 || !strings.Contains(errb.String(), "invalid-encoding") {
			t.Errorf("%s: code=%d stdout=%d err=%.200s", name, code, out.Len(), errb.String())
		}
	}
}

// Env values match docker compose config for the same bytes in the project .env (via interpolation)
// and a service env_file, or the input is refused (exit 3) where the engine
// refuses it. Never a silently changed value marked proven.
func TestEnvGrammarMatchesTheEngine(t *testing.T) {
	cases := []struct {
		name, body, key, want string
	}{
		{"double-quoted \\n", `COLOR="first\nsecond"`, "COLOR", "first\nsecond"},
		{"single-quoted backslash", `COLOR='a\b'`, "COLOR", `a\b`},
		{"single-quoted multiline", "COLOR='first\nsecond'", "COLOR", "first\nsecond"},
		{"double-quoted multiline", "COLOR=\"first\nsecond\"", "COLOR", "first\nsecond"},
		{"unquoted comment and spaces", "COLOR=  spaced value   # comment", "COLOR", "spaced value"},
		{"unquoted hash without space", "COLOR=value#nocomment", "COLOR", "value#nocomment"},
		{"unquoted backslash n", `COLOR=unq\nescaped`, "COLOR", `unq\nescaped`},
		{"double-quoted escapes", `COLOR="dq \t \\ \" \a \b \x41 \z é \0101 \012 end"`, "COLOR", "dq \t \\ \" \a \b \\x41 \\z é A \\12 end"},
		{"single-quoted escapes", `COLOR='sq \n \' \\ \z'`, "COLOR", `sq \n ' \\ \z`},
		{"single-quoted double backslash before quote closes", `COLOR='a\\'`, "COLOR", `a\\`},
		{"double-quoted double backslash then b", `COLOR="a\\b\"c"`, "COLOR", `a\b"c`},
		{"double-quoted double backslash before quote closes", `COLOR="a\\"`, "COLOR", `a\`},
		{"double-quoted octal and unknown escapes", `COLOR="\0 \U0001F600 \u12 \101 \v\f"`, "COLOR", "\\ \\U0001F600 \\u12 \\101 \v\f"},
		{"yaml-style colon", "COLOR: yaml-style", "COLOR", "yaml-style"},
		{"export prefix", "export COLOR=exp", "COLOR", "exp"},
		{"text after closing quote", `COLOR="a" OTHER=2`, "COLOR", "a"},
		{"quoted with leading space", `COLOR=  "lead and trail  "`, "COLOR", "lead and trail  "},
		{"crlf", "COLOR=crlf\r\nX=1\r", "COLOR", "crlf"},
	}
	for _, c := range cases {
		dir := writeProbeProject(t, map[string]string{"compose.yaml": envProbeService, ".env": c.body + "\n", "app.env": c.body + "\n"})
		code, vars, errs := containerVars(t, dir)
		if code != exitcode.OK {
			t.Errorf("%s: code=%d err=%.200s", c.name, code, errs)
			continue
		}
		if got := vars[c.key]; got != c.want {
			t.Errorf("%s: env_file %s=%q want %q", c.name, c.key, got, c.want)
		}
		if got := vars["FROM_PROJECT"]; got != c.want {
			t.Errorf("%s: .env interpolation FROM_PROJECT=%q want %q", c.name, got, c.want)
		}
	}
	// Keys the engine keeps, including dotted and bracketed names.
	dir := writeProbeProject(t, map[string]string{"compose.yaml": envProbeService, "app.env": "FOO.BAR=blue\nFOO-BAR=y\nA[0]=x\nCOLOR=green\n", ".env": "COLOR=green\n"})
	if code, vars, errs := containerVars(t, dir); code != exitcode.OK || vars["FOO.BAR"] != "blue" || vars["FOO-BAR"] != "y" || vars["A[0]"] != "x" {
		t.Errorf("valid engine names: code=%d vars=%v err=%s", code, vars, errs)
	}
	// Inputs the engine refuses are refused (exit 3), in either file.
	refused := map[string]string{
		"unterminated quote": `COLOR="unterminated`,
		"space in key":       "BAD KEY=x",
		"dollar in key":      "BAD$=x",
		"junk after quote":   `COLOR='it''s'`,
	}
	for name, body := range refused {
		for _, file := range []string{".env", "app.env"} {
			files := map[string]string{"compose.yaml": envProbeService, ".env": "COLOR=ok\n", "app.env": "COLOR=ok\n"}
			files[file] = body + "\n"
			dir := writeProbeProject(t, files)
			rt, out, errb := reportRT(dir)
			if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != exitcode.Input || out.Len() != 0 {
				t.Errorf("%s in %s: code=%d err=%.160s", name, file, code, errb.String())
			}
		}
	}
}

// The same comparison against the local engine, when one is on PATH.
func TestLiveEnvGrammarMatchesEngine(t *testing.T) {
	testenv.RequireDocker(t)
	docker, _ := exec.LookPath("docker") // present: RequireDocker returned
	body := strings.Join([]string{
		`A1="first\nsecond"`, `A2='a\b'`, "A3='multi\nline'", "A4=  spaced value   # comment",
		`A5="dq \t \\ \" \a \b \x41 \z é end"`, `A6='sq \n \' \\ \z'`, "A7: yaml-style",
		"export A8=exp", `A9="a" A10=2`, "FOO.BAR=blue", "A11=value#x", `A12=unq\n`,
	}, "\n") + "\n"
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    env_file: app.env\n", "app.env": body})
	cmd := exec.Command(docker, "compose", "--project-directory", dir, "-f", filepath.Join(dir, "compose.yaml"), "config", "--format", "json")
	cmd.Env = append(os.Environ(), "COMPOSE_PROJECT_NAME=envgrammar")
	raw, err := cmd.Output()
	if err != nil {
		t.Skipf("docker compose config unavailable: %v", err)
	}
	var cfg struct {
		Services map[string]struct {
			Environment map[string]*string `json:"environment"`
		} `json:"services"`
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	_, vars, _ := containerVars(t, dir)
	engineEnv := cfg.Services["web"].Environment
	for k, v := range engineEnv {
		want := strings.ReplaceAll(*v, "$$", "$") // the engine's dump escapes $
		if vars[k] != want {
			t.Errorf("%s: lens %q engine %q", k, vars[k], want)
		}
	}
	if len(vars) != len(engineEnv) {
		t.Errorf("lens keys %d engine keys %d: %v", len(vars), len(engineEnv), vars)
	}
}

// A mixed short/long env_file list loads every entry in order.
func TestMixedEnvFileListKeepsEveryEntryInOrder(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    env_file:\n      - a.env\n      - path: b.env\n      - c.env\n",
		"a.env":        "ONLY_A=from-a\nCOLOR=from-a\n",
		"b.env":        "ONLY_B=from-b\nCOLOR=from-b\n",
		"c.env":        "ONLY_C=from-c\nCOLOR=from-c\n",
	})
	code, vars, errs := containerVars(t, dir)
	if code != exitcode.OK || vars["COLOR"] != "from-c" || vars["ONLY_A"] != "from-a" || vars["ONLY_B"] != "from-b" || vars["ONLY_C"] != "from-c" {
		t.Fatalf("code=%d vars=%v err=%s", code, vars, errs)
	}
}

// format: raw keeps values byte for byte (as the engine does).
func TestRawFormatPreservesBytes(t *testing.T) {
	rawSvc := "services:\n  web:\n    image: alpine:3.21\n    env_file:\n      - path: app.env\n        format: raw\n"
	dir := writeProbeProject(t, map[string]string{
		"compose.yaml": rawSvc,
		"app.env":      "# comment\nCOLOR=\"green\"\nQUOTED='blue'\nLITERAL=$VAR\nSPACED= x y  \nTRAIL=val # c\nX=a=b\n  IND=1\nCR=1\r\n",
	})
	code, vars, errs := containerVars(t, dir)
	want := map[string]string{"COLOR": `"green"`, "QUOTED": `'blue'`, "LITERAL": "$VAR", "SPACED": " x y  ", "TRAIL": "val # c", "X": "a=b", "IND": "1", "CR": "1"}
	if code != exitcode.OK {
		t.Fatalf("code=%d err=%s", code, errs)
	}
	for k, w := range want {
		if vars[k] != w {
			t.Errorf("%s=%q want %q", k, vars[k], w)
		}
	}
	for _, body := range []string{"BAD KEY=x\n", "=x\n"} {
		d := writeProbeProject(t, map[string]string{"compose.yaml": rawSvc, "app.env": body})
		if c, _, _ := containerVars(t, d); c != exitcode.Input {
			t.Errorf("raw %q: code=%d (the engine refuses it)", body, c)
		}
	}
}
