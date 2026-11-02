// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

// stubActionRoot is a minimal "source tree" the wrappers can build: its
// cmd/composelens records the argv it was given, so the test sees exactly
// what each wrapper passes to the CLI.
func stubActionRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	main := `package main

import (
	"encoding/json"
	"os"
)

func main() {
	b, _ := json.Marshal(os.Args[1:])
	_ = os.WriteFile(os.Getenv("STUB_ARGV"), b, 0o644)
}
`
	for name, body := range map[string]string{
		"go.mod":                  "module stubaction\n\ngo 1.22\n",
		"cmd/composelens/main.go": main,
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func wrapperShells(t *testing.T) map[string][]string {
	t.Helper()
	scripts := filepath.Join("..", "..", "scripts")
	ps, _ := filepath.Abs(filepath.Join(scripts, "composelens-action.ps1"))
	sh, _ := filepath.Abs(filepath.Join(scripts, "composelens-action.sh"))
	out := map[string][]string{}
	for _, name := range []string{"pwsh", "powershell"} {
		if p, err := exec.LookPath(name); err == nil {
			out["powershell"] = []string{p, "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", ps}
			break
		}
	}
	bash := ""
	if runtime.GOOS == "windows" {
		// Git for Windows bash; System32\bash.exe is WSL and is not used.
		if p := `C:\Program Files\Git\bin\bash.exe`; fileExists(p) {
			bash = p
		}
	} else if p, err := exec.LookPath("bash"); err == nil {
		bash = p
	}
	if bash != "" {
		out["bash"] = []string{bash, filepath.ToSlash(sh)}
	}
	return out
}

func fileExists(p string) bool {
	st, err := os.Stat(p)
	return err == nil && !st.IsDir()
}

// Both Action wrappers split file and profile lists on commas,
// semicolons and real CR/LF line breaks only, so names containing the
// letters r and n survive, and both pass the same argv to the CLI.
func TestActionWrappersSplitInputListsAlike(t *testing.T) {
	shells := wrapperShells(t)
	if len(shells) == 0 {
		t.Skip("neither PowerShell nor bash is available")
	}
	root := stubActionRoot(t)
	cases := []struct {
		name, files, profiles string
		want                  []string
	}{
		{"comma", "a.yaml,C:/repo/rn dir/normal.yaml", "prod,normal",
			[]string{"--file", "a.yaml", "--file", "C:/repo/rn dir/normal.yaml", "--profile", "prod", "--profile", "normal"}},
		{"newline and crlf", "a.yaml\nnormal.yaml", "prod\r\nnormal\n",
			[]string{"--file", "a.yaml", "--file", "normal.yaml", "--profile", "prod", "--profile", "normal"}},
		{"semicolon and spaces", "", " prod ; normal ",
			[]string{"--profile", "prod", "--profile", "normal"}},
	}
	for shell, argv := range shells {
		for _, c := range cases {
			tmp := t.TempDir()
			rec := filepath.Join(tmp, "argv.json")
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Env = append(os.Environ(),
				"COMPOSELENS_ACTION_PATH="+filepath.ToSlash(root),
				"RUNNER_TEMP="+filepath.ToSlash(tmp),
				"INPUT_PROJECT_DIRECTORY=proj",
				"INPUT_FILES="+c.files,
				"INPUT_PROFILES="+c.profiles,
				"INPUT_FAIL_ON=never",
				"STUB_ARGV="+rec,
				"GITHUB_OUTPUT=",
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s %s: %v\n%s", shell, c.name, err, out)
			}
			raw, err := os.ReadFile(rec)
			if err != nil {
				t.Fatalf("%s %s: CLI not invoked: %v", shell, c.name, err)
			}
			var got []string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			want := append([]string{"check", "--github", "--project-directory", "proj"}, c.want...)
			if !reflect.DeepEqual(got, want) {
				t.Errorf("%s %s:\n got  %s\n want %s", shell, c.name, strings.Join(got, " | "), strings.Join(want, " | "))
			}
		}
	}
}

// stubEnvRoot is a source tree whose cmd/composelens records, for each output variable, whether it
// reached the CLI and with which value.
func stubEnvRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	main := `package main

import (
	"encoding/json"
	"os"
)

func main() {
	got := map[string]*string{}
	for _, k := range []string{"COMPOSELENS_JSON_PATH", "COMPOSELENS_SARIF_PATH", "COMPOSELENS_GITHUB_SUMMARY", "GITHUB_STEP_SUMMARY"} {
		if v, ok := os.LookupEnv(k); ok {
			got[k] = &v
		} else {
			got[k] = nil
		}
	}
	b, _ := json.Marshal(got)
	_ = os.WriteFile(os.Getenv("STUB_ENV"), b, 0o644)
}
`
	for name, body := range map[string]string{
		"go.mod":                  "module stubaction\n\ngo 1.22\n",
		"cmd/composelens/main.go": main,
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// Disabled outputs must reach the CLI with their environment paths unset.
// emit-summary=false also clears GITHUB_STEP_SUMMARY from the child, while
// enabled and default outputs keep their artifact paths and step summary.
func TestActionWrappersClearDisabledOutputs(t *testing.T) {
	shells := wrapperShells(t)
	if len(shells) == 0 {
		t.Skip("neither PowerShell nor bash is available")
	}
	root := stubEnvRoot(t)
	outputs := []string{"COMPOSELENS_JSON_PATH", "COMPOSELENS_SARIF_PATH", "COMPOSELENS_GITHUB_SUMMARY"}
	cases := []struct {
		name, emit string // emit = value of all three emit-* inputs ("" = the default, true)
		enabled    bool
	}{
		{"all false", "false", false},
		{"all true", "true", true},
		{"defaults", "", true},
	}
	for shell, argv := range shells {
		for _, c := range cases {
			tmp := t.TempDir()
			rec := filepath.Join(tmp, "env.json")
			step := filepath.ToSlash(filepath.Join(tmp, "step-summary.md"))
			cmd := exec.Command(argv[0], argv[1:]...)
			cmd.Env = append(os.Environ(),
				"COMPOSELENS_ACTION_PATH="+filepath.ToSlash(root),
				"RUNNER_TEMP="+filepath.ToSlash(tmp),
				"INPUT_FAIL_ON=never",
				"INPUT_EMIT_JSON="+c.emit,
				"INPUT_EMIT_SARIF="+c.emit,
				"INPUT_EMIT_SUMMARY="+c.emit,
				"STUB_ENV="+rec,
				"GITHUB_OUTPUT=",
				"GITHUB_STEP_SUMMARY="+step,
				// stale destinations a workflow could have set earlier in the job
				"COMPOSELENS_JSON_PATH="+filepath.ToSlash(filepath.Join(tmp, "stale.json")),
				"COMPOSELENS_SARIF_PATH="+filepath.ToSlash(filepath.Join(tmp, "stale.sarif")),
				"COMPOSELENS_GITHUB_SUMMARY="+filepath.ToSlash(filepath.Join(tmp, "stale.md")),
			)
			if out, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("%s %s: %v\n%s", shell, c.name, err, out)
			}
			raw, err := os.ReadFile(rec)
			if err != nil {
				t.Fatalf("%s %s: CLI not invoked: %v", shell, c.name, err)
			}
			var got map[string]*string
			if err := json.Unmarshal(raw, &got); err != nil {
				t.Fatal(err)
			}
			for _, k := range outputs {
				v := got[k]
				switch {
				case !c.enabled && v != nil:
					t.Errorf("%s %s: disabled %s reached the CLI as %q", shell, c.name, k, *v)
				case c.enabled && (v == nil || strings.Contains(*v, "stale")):
					t.Errorf("%s %s: enabled %s should be the wrapper's own path, got %v", shell, c.name, k, v)
				}
			}
			s := got["GITHUB_STEP_SUMMARY"]
			if !c.enabled && s != nil {
				t.Errorf("%s %s: emit-summary=false left GITHUB_STEP_SUMMARY=%q for the CLI", shell, c.name, *s)
			}
			if c.enabled && (s == nil || *s != step) {
				t.Errorf("%s %s: GITHUB_STEP_SUMMARY should pass through unchanged, got %v", shell, c.name, s)
			}
		}
	}
}
