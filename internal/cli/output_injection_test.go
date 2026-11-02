// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// injectionCompose carries keys and a value that try to start a GitHub
// workflow command, break out of a Markdown code span, and smuggle C1, bidi
// and zero-width characters.
const injectionCompose = "services:\n" +
	"  api:\n" +
	"    image: nginx\n" +
	"    labels:\n" +
	"      \"a` [click](https://example.invalid/x) ![p](https://example.invalid/p.png) `b\": \"postgres://u:pw_abcdef@h/db\"\n" +
	`      "line1\n::error title=Forged::forged annotation": "postgres://u:pw_abcdef2@h/db"` + "\n" +
	`      "cr\r::warning::forged by cr": "postgres://u:pw_abcdef3@h/db"` + "\n" +
	`      "b\u009b31mC1\u202eevil\u200bzw": "postgres://u:termpw5678@h/d"` + "\n" +
	`      plain: "first\n::notice::forged from a value"` + "\n"

var ownAnnotation = regexp.MustCompile(`^::(warning|error|notice)( file=[^:,]*(,line=\d+(,col=\d+)?)?)?::CHK0\d `)

func startsWorkflowCommand(out string) []string {
	var bad []string
	for _, line := range strings.FieldsFunc(out, func(r rune) bool { return r == '\n' || r == '\r' }) {
		if strings.HasPrefix(strings.TrimLeft(line, " \t"), "::") {
			bad = append(bad, line)
		}
	}
	return bad
}

func TestHumanOutputNeverStartsAWorkflowCommand(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": injectionCompose})
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	for _, args := range [][]string{{"check"}, {"inspect"}, {"explain", "--all"}} {
		code, out, errs := runIn(t, dir, nil, args...)
		if code != 0 {
			t.Fatalf("%v: exit %d %s", args, code, errs)
		}
		if bad := startsWorkflowCommand(out + errs); len(bad) > 0 {
			t.Errorf("%v starts a workflow command: %q", args, bad)
		}
	}
}

func TestGitHubOutputOnlyEmitsItsOwnCommands(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": injectionCompose})
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("GITHUB_STEP_SUMMARY", "")
	code, out, errs := runIn(t, dir, nil, "check", "--github")
	if code != 0 || len(startsWorkflowCommand(out)) == 0 {
		t.Fatalf("check --github: exit %d, %d annotations %s", code, len(startsWorkflowCommand(out)), errs)
	}
	for _, line := range startsWorkflowCommand(out) {
		// Every command is one ComposeLens annotation; a forged line such as
		// "::error title=Forged::" does not have this shape.
		if !ownAnnotation.MatchString(line) {
			t.Errorf("unexpected workflow command %q", line)
		}
	}
}

func TestJobSummaryKeepsMarkdownInert(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": injectionCompose})
	summary := filepath.Join(t.TempDir(), "summary.md")
	t.Setenv("GITHUB_WORKSPACE", "")
	t.Setenv("GITHUB_STEP_SUMMARY", summary)
	runIn(t, dir, nil, "check", "--github")
	raw, err := os.ReadFile(summary)
	if err != nil {
		t.Fatal(err)
	}
	md := string(raw)
	if bad := startsWorkflowCommand(md); len(bad) > 0 {
		t.Errorf("summary starts a workflow command: %q", bad)
	}
	for _, line := range strings.Split(md, "\n") {
		if !strings.Contains(line, "click") {
			continue
		}
		// The whole message after " — " must be one code span that the key's
		// own backticks cannot close, so no part of it renders as Markdown.
		_, msg, _ := strings.Cut(line, " — ")
		if !wholeCodeSpan(msg) {
			t.Errorf("Markdown link from a key is live in the summary: %q", line)
		}
	}
}

func TestTerminalControlsAreShownEscaped(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": injectionCompose})
	for _, args := range [][]string{{"check"}, {"inspect"}, {"explain", "--all"}} {
		_, out, errs := runIn(t, dir, nil, args...)
		for _, r := range []string{"\u009b", "\u202e", "\u200b", "\r"} {
			if strings.Contains(out+errs, r) {
				t.Errorf("%v printed control character %q raw", args, r)
			}
		}
	}
	_, out, _ := runIn(t, dir, nil, "inspect")
	if !strings.Contains(out, `\u202e`) {
		t.Errorf("inspect does not show the bidi override escaped:\n%s", out)
	}
}

// wholeCodeSpan reports whether s is exactly one CommonMark code span: it
// opens with a run of N backticks, ends with a run of N backticks, and holds
// no other run of exactly N backticks.
func wholeCodeSpan(s string) bool {
	n := 0
	for n < len(s) && s[n] == '`' {
		n++
	}
	if n == 0 || len(s) < 2*n || !strings.HasSuffix(s, strings.Repeat("`", n)) {
		return false
	}
	if len(s) > 2*n && s[len(s)-n-1] == '`' {
		return false
	}
	inner := s[n : len(s)-n]
	for i := 0; i < len(inner); {
		if inner[i] != '`' {
			i++
			continue
		}
		j := i
		for j < len(inner) && inner[j] == '`' {
			j++
		}
		if j-i == n {
			return false
		}
		i = j
	}
	return true
}
