// SPDX-License-Identifier: Apache-2.0

package reproduction

import (
	"strings"
	"testing"
)

func TestGenerateDeterministicAndOrdered(t *testing.T) {
	in := Input{
		ProjectDir: `C:\proj`,
		Files:      []string{`C:\proj\compose.yaml`, `C:\proj\overlay.yaml`},
		EnvFiles:   []string{`C:\proj\extra.env`},
		Profiles:   []string{"debug", "tools"},
	}
	a := Generate(in)
	b := Generate(in)
	if a.Line != b.Line || strings.Join(a.Argv, "\x00") != strings.Join(b.Argv, "\x00") {
		t.Fatalf("not deterministic\n%q\n%q", a.Line, b.Line)
	}
	want := []string{
		"docker", "compose",
		"--project-directory", `C:\proj`,
		"-f", `C:\proj\compose.yaml`,
		"-f", `C:\proj\overlay.yaml`,
		"--env-file", `C:\proj\extra.env`,
		"--profile", "debug",
		"--profile", "tools",
		"config",
	}
	if len(a.Argv) != len(want) {
		t.Fatalf("argv len %d want %d: %v", len(a.Argv), len(want), a.Argv)
	}
	for i := range want {
		if a.Argv[i] != want[i] {
			t.Fatalf("argv[%d]=%q want %q", i, a.Argv[i], want[i])
		}
	}
	if !strings.HasSuffix(a.Line, " config") {
		t.Fatalf("line=%s", a.Line)
	}
}

func TestQuotePathsWithSpaces(t *testing.T) {
	in := Input{ProjectDir: `C:\Users\me\My Project`, Files: []string{`C:\Users\me\My Project\compose.yaml`}}
	cmd := Generate(in)
	if cmd.Argv[3] != `C:\Users\me\My Project` {
		t.Fatalf("argv project %q", cmd.Argv[3])
	}
	if !strings.Contains(cmd.Line, `'C:\Users\me\My Project'`) {
		t.Fatalf("line not POSIX-single-quoted: %s", cmd.Line)
	}
	if strings.Contains(cmd.Line, `"C:\Users\me\My Project"`) {
		t.Fatalf("must not double-quote: %s", cmd.Line)
	}
	if strings.Contains(cmd.Line, `\\Users`) {
		t.Fatal("must not escape backslashes in quoted Windows paths")
	}
}

func TestQuotePOSIXAllowlistAndMetacharacters(t *testing.T) {
	if Quote("") != "''" {
		t.Fatalf("empty: %q", Quote(""))
	}
	if Quote("docker") != "docker" || Quote("compose.yaml") != "compose.yaml" || Quote("C") != "C" {
		t.Fatal("safe tokens must stay bare")
	}
	if Quote(`C:\proj`) != `'C:\proj'` {
		t.Fatalf("backslash must be quoted: %s", Quote(`C:\proj`))
	}
	cases := []string{
		"$(touch INJECTED)",
		"`touch INJECTED`",
		"${HOME}",
		"a;b",
		"a&b",
		"a&&b",
		"a|b",
		"a||b",
		"a>b",
		"a>>b",
		"a<b",
		"a*b",
		"a?b",
		"a[b]",
		"a(b)",
		"a{b}",
		"~root",
		"#hash",
		"a!b",
		"a b",
		"a\tb",
		"a\nb",
		`a"b`,
		"a'b",
		`a\b`,
		" inj $(touch INJECTED) ; echo hi",
	}
	for _, tok := range cases {
		got := Quote(tok)
		if !strings.HasPrefix(got, "'") || !strings.HasSuffix(got, "'") {
			t.Fatalf("expected single quotes for %q got %s", tok, got)
		}
		if strings.Contains(tok, "'") {
			if !strings.Contains(got, `'\''`) {
				t.Fatalf("embedded quote escape missing: %s", got)
			}
		} else if got != "'"+tok+"'" {
			t.Fatalf("literal wrap %q -> %s", tok, got)
		}
	}
	if Quote("it's") != `'it'\''s'` {
		t.Fatalf("embedded single quote: %s", Quote("it's"))
	}
}

func TestRejectSecrets(t *testing.T) {
	cmd := Generate(Input{ProjectDir: "p", Files: []string{"compose.yaml"}})
	if err := RejectSecrets(cmd, []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}); err != nil {
		t.Fatal(err)
	}
	bad := Generate(Input{ProjectDir: "p", Files: []string{"compose.yaml"}, Profiles: []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}})
	if err := RejectSecrets(bad, []string{"ghp_abcdefghijklmnopqrstuvwxyz0123456789"}); err == nil {
		t.Fatal("expected reject inlined secret profile")
	}
}

func TestGenerateOmitsEmpty(t *testing.T) {
	cmd := Generate(Input{ProjectDir: "p", Files: []string{"", "a.yaml"}, EnvFiles: []string{" "}, Profiles: []string{""}})
	joined := strings.Join(cmd.Argv, " ")
	if strings.Contains(joined, "-f  ") || strings.Count(joined, "-f ") != 1 {
		t.Fatalf("argv=%v", cmd.Argv)
	}
}
