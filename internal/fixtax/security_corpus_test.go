// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"composelens/internal/check"
	"composelens/internal/cli"
	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/redact"
)

const (
	probeGHP         = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	probeGHO         = "gho_abcdefghijklmnopqrstuvwxyz0123456789"
	probeAKIA        = "AKIAIOSFODNN7EXAMPLE"
	probeAWSSecret   = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
	probeURL         = "https://demo-user:synthetic-probe-password@example.invalid/db"
	probeURLPass     = "synthetic-probe-password"
	probeKeyed       = "keyed-probe-password-value-zz"
	probeHighEntropy = "aB3xY9mK2pQ7nx5wR8tV1cZ4jH6uD0##"
	probePathGHP     = "/run/secrets/ghp_abcdefghijklmnopqrstuvwxyz0123456789"
)

type corpusSurface struct {
	name string
	kind string
	args []string
}

type secretBatteryCase struct {
	id     string
	field  string
	probes []string
	body   string
	setup  func(dir string) error
}

type inertBatteryCase struct {
	id   string
	body string
}

func TestSecurityCorpusSecretBattery(t *testing.T) {
	cases := secretBatteryCases()
	var rows []string
	rows = append(rows, "case\tfield\tsurfaces\tredacted")
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			dir := writeSecretProject(t, tc)
			var names []string
			for _, s := range corpusSurfaces(dir) {
				names = append(names, s.name)
				code, out, errb := runCorpusCLI(t, dir, s.args)
				blob := out + errb
				for _, p := range tc.probes {
					if p != "" && strings.Contains(blob, p) {
						t.Fatalf("CRITICAL: raw secret leaked on %s (exit %d)", s.name, code)
					}
				}
				if code == exitcode.Safety {
					t.Fatalf("CRITICAL: fail-closed on %s — redaction missed a value the guard caught", s.name)
				}
				if code != exitcode.OK {
					t.Fatalf("%s exit=%d stderr=%s stdout=%s", s.name, code, errb, trimForLog(out))
				}
				assertSurfaceWellFormed(t, s, out)
			}
			rows = append(rows, fmt.Sprintf("%s\t%s\t%s\tredacted=yes", tc.id, tc.field, strings.Join(names, ",")))
		})
	}
	writeResultFile(t, "secret-battery-table.txt", strings.Join(rows, "\n")+"\n")
}

func TestSecurityCorpusInertBattery(t *testing.T) {
	cases := inertBatteryCases()
	var rows []string
	rows = append(rows, "case\tsurface\tinert")
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			dir := writeInertProject(t, tc.body)
			for _, s := range corpusSurfaces(dir) {
				code, out, errb := runCorpusCLI(t, dir, s.args)
				if code != exitcode.OK {
					t.Fatalf("%s exit=%d stderr=%s stdout=%s", s.name, code, errb, trimForLog(out))
				}
				blob := out + errb
				if bytes.Contains([]byte(blob), []byte{0x1b}) || bytes.Contains([]byte(blob), []byte{0x00}) || bytes.Contains([]byte(blob), []byte{'\r'}) {
					t.Fatalf("CRITICAL: raw control/ANSI/CR on %s", s.name)
				}
				assertSurfaceWellFormed(t, s, out)
				if s.kind == "json" || s.kind == "sarif" {
					if strings.Contains(out, "<script>") {
						t.Fatalf("JSON/SARIF left <script> unescaped on %s", s.name)
					}
				}
				rows = append(rows, fmt.Sprintf("%s\t%s\tinert=yes", tc.id, s.name))
			}
		})
	}
	writeResultFile(t, "inert-battery-table.txt", strings.Join(rows, "\n")+"\n")
}

func TestSecurityCorpusReportXSSCatalog(t *testing.T) {
	cat, err := LoadCatalog(filepath.Join(fixturesRoot(t), "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"security.report-xss.xss-script",
		"security.report-xss.xss-event",
		"security.report-xss.xss-javascript-url",
	}
	found := map[string]Fixture{}
	for _, fx := range cat.Fixtures {
		found[fx.ID] = fx
	}
	var lines []string
	lines = append(lines, "id\tnote\tcatalog-assertion")
	for _, id := range want {
		fx, ok := found[id]
		if !ok {
			t.Fatalf("missing report XSS fixture %s", id)
		}
		if !strings.Contains(fx.Provenance.Note, "report-xss") {
			t.Fatalf("%s provenance.note=%q", id, fx.Provenance.Note)
		}
		if fx.Expected.Engine != EnginePending {
			t.Fatalf("%s engine=%s (engine comparison is pending)", id, fx.Expected.Engine)
		}
		if fx.Expected.Local.Assertion != "files-exist" {
			t.Fatalf("%s assertion=%s", id, fx.Expected.Local.Assertion)
		}
		lines = append(lines, id+"\treport-xss\tfiles-exist")
	}
	writeResultFile(t, "html-fixtures.txt", strings.Join(lines, "\n")+"\n")
}

func TestSecurityKindRequiresRationaleOnCatalog(t *testing.T) {
	cat, err := LoadCatalog(filepath.Join(fixturesRoot(t), "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, fx := range cat.Fixtures {
		if fx.Kind != KindSecurity {
			continue
		}
		n++
		if fx.Rationale.Type != "docs" && fx.Rationale.Type != "compose-spec" {
			t.Fatalf("%s rationale.type=%q", fx.ID, fx.Rationale.Type)
		}
		if !strings.HasPrefix(fx.Rationale.Ref, "https://") {
			t.Fatalf("%s rationale.ref=%q", fx.ID, fx.Rationale.Ref)
		}
		if strings.Contains(fx.Rationale.Ref, "github.com/docker/compose/issues/") {
			t.Fatalf("%s fabricated-or-banned issue URL", fx.ID)
		}
	}
	if n < 20 {
		t.Fatalf("security rows=%d want at least secret+inert+report-xss set", n)
	}
}

func TestOrdinaryPathsAndValuesNotOverRedacted(t *testing.T) {
	// Re-validate after any redact/guard strengthening: ordinary paths stay visible.
	ordinary := []string{
		`C:\Windows\System32`,
		`/var/log/app.log`,
		`./relative/path.env`,
		`postgres://localhost:5432/app`,
		`alpine`,
		`demo-inline`,
	}
	for _, p := range ordinary {
		if redact.LooksLikeSecret(p) {
			t.Fatalf("ordinary value over-redacted: %q", p)
		}
	}
	if !redact.LooksLikeSecret(probeGHP) || !redact.MustRedact("API_TOKEN", probeGHP) {
		t.Fatal("secret classifier weakened")
	}
}

func secretBatteryCases() []secretBatteryCase {
	q := strconv.Quote
	header := "services:\n  web:\n    image: alpine\n    hostname: ${COLOR:-web}\n"
	return []secretBatteryCase{
		{
			id: "ghp.environment-map", field: "environment-map", probes: []string{probeGHP},
			body: header + "    environment:\n      API_TOKEN: " + probeGHP + "\n",
		},
		{
			id: "gho.environment-map", field: "environment-map", probes: []string{probeGHO},
			body: header + "    environment:\n      API_TOKEN: " + probeGHO + "\n",
		},
		{
			id: "aws.environment-map", field: "environment-map", probes: []string{probeAKIA, probeAWSSecret},
			body: header + "    environment:\n      AWS_ACCESS_KEY_ID: " + probeAKIA + "\n      AWS_SECRET_ACCESS_KEY: " + q(probeAWSSecret) + "\n",
		},
		{
			id: "url.environment-map", field: "environment-map", probes: []string{probeURL, probeURLPass},
			body: header + "    environment:\n      DATABASE_URL: " + q(probeURL) + "\n",
		},
		{
			id: "keyed.environment-map", field: "environment-map", probes: []string{probeKeyed},
			body: header + "    environment:\n      PASSWORD: " + probeKeyed + "\n      TOKEN: " + probeKeyed + "\n      SECRET: " + probeKeyed + "\n      API_KEY: " + probeKeyed + "\n",
		},
		{
			id: "high-entropy.environment-map", field: "environment-map", probes: []string{probeHighEntropy},
			body: header + "    environment:\n      NOTE: " + q(probeHighEntropy) + "\n",
		},
		{
			id: "ghp.environment-list", field: "environment-list", probes: []string{probeGHP},
			body: header + "    environment:\n      - API_TOKEN=" + probeGHP + "\n",
		},
		{
			id: "ghp.labels", field: "labels", probes: []string{probeGHP},
			body: header + "    labels:\n      api.token: " + probeGHP + "\n",
		},
		{
			id: "ghp.command", field: "command", probes: []string{probeGHP},
			body: header + "    command: [\"echo\", " + q(probeGHP) + "]\n",
		},
		{
			id: "ghp.entrypoint", field: "entrypoint", probes: []string{probeGHP},
			body: header + "    entrypoint: [\"echo\", " + q(probeGHP) + "]\n",
		},
		{
			id: "ghp.image", field: "image", probes: []string{probeGHP},
			body: "services:\n  web:\n    image: " + probeGHP + "\n    hostname: ${COLOR:-web}\n",
		},
		{
			id: "ghp.volumes", field: "volumes", probes: []string{probeGHP, probePathGHP},
			body: header + "    volumes:\n      - " + q(probePathGHP+":/in") + "\n",
		},
		{
			id: "ghp.build-args", field: "build.args", probes: []string{probeGHP},
			body: "services:\n  web:\n    hostname: ${COLOR:-web}\n    build:\n      context: .\n      args:\n        API_TOKEN: " + probeGHP + "\n",
			setup: func(dir string) error {
				return os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0o644)
			},
		},
		{
			id: "ghp.path-embedded", field: "volumes-path", probes: []string{probeGHP, probePathGHP},
			body: header + "    volumes:\n      - " + q(probePathGHP+":/in") + "\n",
		},
	}
}

func inertBatteryCases() []inertBatteryCase {
	header := "services:\n  web:\n    image: alpine\n    hostname: ${COLOR:-web}\n    environment:\n"
	long := strings.Repeat("A", 8000)
	return []inertBatteryCase{
		{id: "html-script", body: header + "      NOTE: \"<script>alert(1)</script>\"\n"},
		{id: "ansi", body: header + "      NOTE: \"\\u001b[31mRED\\u001b[0m\"\n"},
		{id: "json-yaml-meta", body: header + "      NOTE: " + strconv.Quote(`{"k":"v","q":"a\"b"}`) + "\n"},
		{id: "dollar-interp", body: header + "      NOTE: \"$${HOME}\"\n      CMD: \"$$(whoami)\"\n"},
		{id: "crlf", body: header + "      NOTE: \"line1\\r\\nline2\"\n"},
		{id: "format-string", body: header + "      NOTE: \"%s%n%x\"\n"},
		{id: "long-value", body: header + "      NOTE: " + strconv.Quote(long) + "\n"},
	}
}

func corpusSurfaces(dir string) []corpusSurface {
	pd := []string{"--project-directory", dir}
	diff := []string{"--left-env-file", "left.env", "--right-env-file", "right.env"}
	return []corpusSurface{
		{name: "inspect-human", kind: "human", args: append([]string{"inspect"}, pd...)},
		{name: "inspect-json", kind: "json", args: append([]string{"inspect", "--json"}, pd...)},
		{name: "explain-human", kind: "human", args: append([]string{"explain", "web"}, pd...)},
		{name: "explain-json", kind: "json", args: append([]string{"explain", "--json", "web"}, pd...)},
		{name: "explain-all-human", kind: "human", args: append([]string{"explain", "--all"}, pd...)},
		{name: "explain-all-json", kind: "json", args: append([]string{"explain", "--all", "--json"}, pd...)},
		{name: "diff-human", kind: "human", args: append(append([]string{"diff"}, diff...), pd...)},
		{name: "diff-json", kind: "json", args: append(append([]string{"diff", "--json"}, diff...), pd...)},
		{name: "check-human", kind: "human", args: append([]string{"check"}, pd...)},
		{name: "check-json", kind: "json", args: append([]string{"check", "--json"}, pd...)},
		{name: "check-sarif", kind: "sarif", args: append([]string{"check", "--sarif"}, pd...)},
		{name: "check-github", kind: "github", args: append([]string{"check", "--github"}, pd...)},
		{name: "differential-human", kind: "human", args: append([]string{"differential"}, pd...)},
		{name: "differential-json", kind: "json", args: append([]string{"differential", "--json"}, pd...)},
	}
}

func runCorpusCLI(t *testing.T, dir string, args []string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	rt := cli.Runtime{
		Stdout: &out,
		Stderr: &errb,
		Cwd:    dir,
		Detect: func() engine.Info { return engine.Info{State: evidence.Absent} },
	}
	code := rt.Run(args)
	return code, out.String(), errb.String()
}

func assertSurfaceWellFormed(t *testing.T, s corpusSurface, out string) {
	t.Helper()
	switch s.kind {
	case "json":
		var v any
		if err := json.Unmarshal([]byte(out), &v); err != nil {
			t.Fatalf("%s JSON invalid: %v", s.name, err)
		}
	case "sarif":
		if err := check.ValidateSARIF([]byte(strings.TrimSpace(out))); err != nil {
			t.Fatalf("%s SARIF invalid: %v", s.name, err)
		}
	case "github":
		if strings.Contains(out, "\x00") {
			t.Fatalf("%s github contains NUL", s.name)
		}
		if strings.Contains(out, "::") {
			if strings.Contains(out, `C:\`) || strings.Contains(out, "/Users/") {
				t.Fatalf("%s github annotation has absolute path", s.name)
			}
		}
	case "human":
		if strings.Contains(out, "\x00") {
			t.Fatalf("%s human contains NUL", s.name)
		}
	}
}

func writeSecretProject(t *testing.T, tc secretBatteryCase) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(tc.body), 0o644); err != nil {
		t.Fatal(err)
	}
	writeDiffEnv(t, dir)
	if tc.setup != nil {
		if err := tc.setup(dir); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func writeInertProject(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	writeDiffEnv(t, dir)
	return dir
}

func writeDiffEnv(t *testing.T, dir string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "left.env"), []byte("COLOR=left\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "right.env"), []byte("COLOR=right\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeResultFile(t *testing.T, name, body string) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_SECURITY_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func trimForLog(s string) string {
	s = strings.ReplaceAll(s, "\x1b", "")
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}
