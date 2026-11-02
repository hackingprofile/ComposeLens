// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/testenv"
)

const (
	anchorReportJSON = "f63568ecbb528a477dd1fea32be2b70aa6bb74ed8aba524bb7b78714f0ebc67e"
	anchorReportHTML = "5b6342b4769aa95a710acd780bda409ecf6c22c67f80f03b4959c78714457886"
)

func portfolioRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		t.Fatal(err)
	}
	return root
}

func chdirRoot(t *testing.T) string {
	t.Helper()
	root := portfolioRoot(t)
	old, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chdir(old) })
	return root
}

func runCLI(t *testing.T, root string, args []string) (int, []byte, []byte) {
	t.Helper()
	var out, errb bytes.Buffer
	rt := Runtime{
		Stdout: &out,
		Stderr: &errb,
		Cwd:    root,
		Detect: func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	code := rt.Run(args)
	return code, out.Bytes(), errb.Bytes()
}

func shaHex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

var (
	numCPURe  = regexp.MustCompile(`"numCPU":\s*\d+`)
	hmacRe    = regexp.MustCompile(`hmac-sha256:[0-9a-f]+`)
	cspHashRe = regexp.MustCompile(`sha256-[A-Za-z0-9+/]{43}=`)
	// The shell and how it was detected are platform facts (SHELL is proven
	// on Linux and macOS; Windows detection is inferred).
	shellRe = regexp.MustCompile(`"shell":\s*"[^"]*"(,\s*"certainty":\s*"[^"]*")?`)
	// OS-neutral goldens: the build platform and the native path
	// separators after {project} are normalized; everything else compares
	// byte for byte.
	platformRe = regexp.MustCompile(`"(os|arch)":\s*"[^"]*"`)
	projPathRe = regexp.MustCompile(`\{project\}[^"\s]*`)
	// The installed Compose release is environment, not report content.
	engineVerRe = regexp.MustCompile(`"engineVersion":\s*"[^"]*"`)
)

func stabilize(raw []byte, root string) []byte {
	s := string(raw)
	abs := root
	s = strings.ReplaceAll(s, strings.ReplaceAll(abs, `\`, `\\`), "{project}")
	s = strings.ReplaceAll(s, abs, "{project}")
	s = numCPURe.ReplaceAllString(s, `"numCPU": 0`)
	s = hmacRe.ReplaceAllString(s, "hmac-sha256:{token}")
	s = shellRe.ReplaceAllStringFunc(s, func(m string) string {
		if strings.Contains(m, `"certainty"`) {
			return `"shell": "{shell}", "certainty": "{shell-certainty}"`
		}
		return `"shell": "{shell}"`
	})
	s = platformRe.ReplaceAllString(s, `"$1": "{$1}"`)
	s = engineVerRe.ReplaceAllString(s, `"engineVersion": "{engine}"`)
	s = projPathRe.ReplaceAllStringFunc(s, func(p string) string {
		return strings.ReplaceAll(strings.ReplaceAll(p, `\\`, "/"), `\`, "/")
	})
	return []byte(s)
}

// stabilizeReport makes a report artifact portable across checkout paths and
// machines: it applies stabilize (absolute project root -> {project}, numCPU,
// hmac) and, for HTML, normalizes the content-derived CSP hashes. This keeps
// the golden anchors a structural regression guard rather than a fingerprint of
// one absolute path. Real CSP-hash correctness stays covered by
// TestHTMLCSPHashPinned on unmodified output.
func stabilizeReport(raw []byte, root string, html bool) []byte {
	out := stabilize(raw, root)
	if html {
		out = cspHashRe.ReplaceAll(out, []byte("sha256-{h}"))
	}
	return out
}

func TestGoldenReportAnchors(t *testing.T) {
	// The anchored package includes the live engine differential section.
	testenv.RequireDocker(t)
	root := chdirRoot(t)
	dir := filepath.Join("fixtures", "check", "required-unset")
	code, out, errb := runCLI(t, root, []string{"report", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatal(string(errb))
	}
	if got := shaHex(stabilizeReport(out, root, false)); got != anchorReportJSON {
		t.Fatalf("report --json sha=%s want %s (portable anchor; re-baseline only on an intended report change)", got, anchorReportJSON)
	}
	code, out, errb = runCLI(t, root, []string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatal(string(errb))
	}
	if got := shaHex(stabilizeReport(out, root, true)); got != anchorReportHTML {
		t.Fatalf("report --html sha=%s want %s (portable anchor; re-baseline only on an intended report change)", got, anchorReportHTML)
	}
}

func TestGoldenStableCLIOutputs(t *testing.T) {
	clearGitHubEnv(t)
	root := chdirRoot(t)
	gdir := filepath.Join(root, "testdata", "golden")
	clean := filepath.Join("fixtures", "check", "clean")
	secret := filepath.Join("fixtures", "check", "secret-inline")
	type row struct {
		name string
		args []string
		code int
	}
	rows := []row{
		{name: "version.json", args: []string{"version", "--json"}, code: 0},
		{name: "doctor.json", args: []string{"doctor", "--json", "--project-directory", clean}, code: 0},
		{name: "inspect.json", args: []string{"inspect", "--json", "--project-directory", clean}, code: 0},
		{name: "explain.json", args: []string{"explain", "--all", "--json", "--project-directory", clean}, code: 0},
		{name: "diff.json", args: []string{"diff", "--json", "--left-profile", "a", "--right-profile", "b", "--project-directory", clean}, code: 0},
		{name: "check.json", args: []string{"check", "--json", "--project-directory", clean}, code: 0},
		{name: "check.human.txt", args: []string{"check", "--project-directory", clean}, code: 0},
		{name: "check.sarif.json", args: []string{"check", "--sarif", "--project-directory", clean}, code: 0},
		{name: "check.github.txt", args: []string{"check", "--github", "--project-directory", secret}, code: 0},
	}
	update := os.Getenv("COMPOSELENS_UPDATE_GOLDEN") == "1"
	for _, r := range rows {
		r := r
		t.Run(r.name, func(t *testing.T) {
			code, out, errb := runCLI(t, root, r.args)
			if code != r.code {
				t.Fatalf("code=%d err=%s", code, errb)
			}
			if bytes.Contains(out, []byte("demo-inline")) || bytes.Contains(errb, []byte("demo-inline")) {
				t.Fatal("secret value in golden surface")
			}
			got := stabilize(out, root)
			path := filepath.Join(gdir, r.name)
			if update {
				if err := os.WriteFile(path, got, 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read golden %s: %v (set COMPOSELENS_UPDATE_GOLDEN=1 once)", path, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("golden drift %s\n got %d bytes want %d (fix the regression; do not re-baseline report anchors)", r.name, len(got), len(want))
			}
		})
	}
}

func TestGoldenDoctorStillHasInputs(t *testing.T) {
	root := chdirRoot(t)
	_, out, errb := runCLI(t, root, []string{"doctor", "--json", "--project-directory", filepath.Join("fixtures", "check", "clean")})
	if len(errb) != 0 && !bytes.Contains(out, []byte(`"inputs"`)) {
		t.Fatalf("err=%s", errb)
	}
	var m map[string]json.RawMessage
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if _, ok := m["inputs"]; !ok {
		t.Fatal("doctor --json lost inputs")
	}
}

func TestPropertyExitCodeDeterminism(t *testing.T) {
	root := chdirRoot(t)
	args := []string{"check", "--json", "--project-directory", filepath.Join("fixtures", "check", "clean")}
	c1, o1, _ := runCLI(t, root, args)
	c2, o2, _ := runCLI(t, root, args)
	if c1 != c2 || c1 != exitcode.OK {
		t.Fatalf("codes %d %d", c1, c2)
	}
	if !bytes.Equal(o1, o2) {
		t.Fatal("nondeterministic check json")
	}
}
