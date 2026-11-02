// SPDX-License-Identifier: Apache-2.0

package reproduction

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/differential"
	"composelens/internal/discover"
	"composelens/internal/engineadapter"
	"composelens/internal/envsrc"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/profiles"
	"composelens/internal/redact"
	"composelens/internal/safety"
	"composelens/internal/testenv"
)

type liveCase struct {
	id       string
	dir      string
	files    []string
	envFiles []string
	profiles []string
}

func TestLiveReproductionMatchesModel(t *testing.T) {
	testenv.RequireDocker(t)
	root := filepath.Join("..", "..", "examples", "reproduce-lab")
	mergeDir, err := filepath.Abs(filepath.Join(root, "merge"))
	if err != nil {
		t.Fatal(err)
	}
	profDir, err := filepath.Abs(filepath.Join(root, "profiles"))
	if err != nil {
		t.Fatal(err)
	}
	envDir, err := filepath.Abs(filepath.Join(root, "envfile"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []liveCase{
		{
			id:    "merge",
			dir:   mergeDir,
			files: []string{filepath.Join(mergeDir, "compose.yaml"), filepath.Join(mergeDir, "overlay.yaml")},
		},
		{
			id:       "profiles",
			dir:      profDir,
			files:    []string{filepath.Join(profDir, "compose.yaml")},
			profiles: []string{"debug"},
		},
		{
			id:       "envfile",
			dir:      envDir,
			files:    []string{filepath.Join(envDir, "compose.yaml")},
			envFiles: []string{filepath.Join(envDir, "extra.env")},
		},
	}
	var table strings.Builder
	table.WriteString("id\tcommand\tlive-version\tmodeled-rows\tmatch\n")
	for _, tc := range cases {
		tc := tc
		t.Run(tc.id, func(t *testing.T) {
			cmd := Generate(Input{
				ProjectDir: tc.dir,
				Files:      tc.files,
				EnvFiles:   tc.envFiles,
				Profiles:   tc.profiles,
			})
			if err := RejectSecrets(cmd, nil); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			out, ver, err := runArgv(ctx, cmd.Argv)
			if err != nil {
				t.Fatalf("run generated command: %v\ncmd=%s\n%s", err, cmd.Line, out)
			}
			eng, err := differential.ParseConfig(out)
			if err != nil {
				t.Fatal(err)
			}
			in, err := internalModel(tc.dir, tc.files, tc.envFiles, tc.profiles, nil)
			if err != nil {
				t.Fatal(err)
			}
			rep := differential.CompareInputs(in, eng, differential.Meta{
				EngineState: engineadapter.StateCaptured,
				Version:     ver,
				Command:     cmd.Line,
				Project:     tc.dir,
			})
			n := 0
			ok := true
			for _, row := range rep.Rows {
				if !ModeledRow(row) {
					continue
				}
				n++
				if row.State != differential.StateMatch {
					ok = false
					t.Errorf("%s %s state=%s internal=%q engine=%q", row.Kind, row.Path, row.State, row.Internal, row.Engine)
				}
			}
			if n == 0 {
				t.Fatal("no modeled compare rows")
			}
			status := "match"
			if !ok {
				status = "divergent"
			}
			fmt.Fprintf(&table, "%s\t%s\t%s\t%d\t%s\n", tc.id, cmd.Line, ver, n, status)
		})
	}
	writeEvidence(t, "per-project-match.txt", table.String())
}

func TestLiveReproductionSecretSafe(t *testing.T) {
	testenv.RequireDocker(t)
	probe := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := Generate(Input{ProjectDir: dir, Files: []string{filepath.Join(dir, "compose.yaml")}})
	if err := RejectSecrets(cmd, []string{probe}); err != nil {
		t.Fatal(err)
	}
	blob := cmd.Line + strings.Join(cmd.Argv, " ")
	if strings.Contains(blob, probe) {
		t.Fatal("raw secret in generated command")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	_, _, err := runArgv(ctx, cmd.Argv)
	if err != nil {
		t.Fatalf("generated command failed: %v", err)
	}
	if err := safety.Guard([]byte(cmd.Line), []string{probe}); err != nil {
		t.Fatal(err)
	}
	writeEvidence(t, "secret-probe.txt", "generated-command-and-cli-contain-raw-secret=false\nin-process-probe-only=true\n")
}

func posixBash(t *testing.T) string {
	t.Helper()
	candidates := []string{
		os.Getenv("COMPOSELENS_BASH"),
		`C:\Program Files\Git\bin\bash.exe`,
		`C:\Program Files\Git\usr\bin\bash.exe`,
	}
	for _, c := range candidates {
		if c == "" {
			continue
		}
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			return c
		}
	}
	p, err := exec.LookPath("bash")
	if err != nil || strings.Contains(strings.ToLower(p), "windowsapps") {
		t.Fatal("POSIX bash required to check copy-paste quoting (Git Bash on Windows)")
	}
	return p
}

func TestLiveCopyPasteLineInertInBash(t *testing.T) {
	bash := posixBash(t)
	parent := t.TempDir()
	hostile := filepath.Join(parent, "inj $(touch INJECTED) ; echo hi")
	if err := os.Mkdir(hostile, 0o755); err != nil {
		t.Fatal(err)
	}
	compose := filepath.Join(hostile, "compose.yaml")
	if err := os.WriteFile(compose, []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	cmd := Generate(Input{ProjectDir: hostile, Files: []string{compose}})
	if cmd.Argv[3] != hostile {
		t.Fatalf("argv project mutated: %q", cmd.Argv[3])
	}
	if strings.Contains(cmd.Line, `"inj $(touch INJECTED)`) {
		t.Fatalf("double-quoted substitution still live: %s", cmd.Line)
	}
	if !strings.Contains(cmd.Line, `'`) {
		t.Fatalf("expected POSIX single quotes: %s", cmd.Line)
	}
	cwd := t.TempDir()
	run := exec.Command(bash, "-c", cmd.Line)
	run.Dir = cwd
	var stderr bytes.Buffer
	run.Stderr = &stderr
	_ = run.Run()
	for _, dir := range []string{cwd, parent, hostile} {
		p := filepath.Join(dir, "INJECTED")
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("canary created at %s\nline=%s\nstderr=%s", p, cmd.Line, stderr.String())
		}
	}
	writeEvidence(t, "canary-inert.txt", "line="+cmd.Line+"\ncanary-created=false\n")
}

func TestLiveBashMetacharactersStayLiteral(t *testing.T) {
	bash := posixBash(t)
	cwd := t.TempDir()
	tokens := []string{
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
		`a"b`,
		"a'b",
		`a\b`,
		"inj $(touch INJECTED) ; echo hi",
	}
	var table strings.Builder
	table.WriteString("token\temitted\tbash-result\n")
	for _, tok := range tokens {
		line := FormatLine([]string{"printf", "--", "%s", tok})
		run := exec.Command(bash, "-c", line)
		run.Dir = cwd
		var out, errb bytes.Buffer
		run.Stdout = &out
		run.Stderr = &errb
		if err := run.Run(); err != nil {
			t.Fatalf("token %q line=%s err=%v stderr=%s", tok, line, err, errb.String())
		}
		if out.String() != tok {
			t.Fatalf("token %q not literal: got %q line=%s", tok, out.String(), line)
		}
		if _, err := os.Stat(filepath.Join(cwd, "INJECTED")); err == nil {
			t.Fatalf("canary created for token %q", tok)
		}
		fmt.Fprintf(&table, "%q\t%s\tliteral/inert\n", tok, Quote(tok))
	}
	writeEvidence(t, "metachar-table.txt", table.String())
}

func TestLiveCopyPasteLineMatchesArgvConfig(t *testing.T) {
	testenv.RequireDocker(t)
	bash := posixBash(t)
	dir, err := filepath.Abs(filepath.Join("..", "..", "examples", "reproduce-lab", "merge"))
	if err != nil {
		t.Fatal(err)
	}
	files := []string{filepath.Join(dir, "compose.yaml"), filepath.Join(dir, "overlay.yaml")}
	cmd := Generate(Input{ProjectDir: dir, Files: files})
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	argvOut, ver, err := runArgv(ctx, cmd.Argv)
	if err != nil {
		t.Fatalf("argv: %v", err)
	}
	run := exec.CommandContext(ctx, bash, "-c", cmd.Line)
	var stdout, stderr bytes.Buffer
	run.Stdout = &stdout
	run.Stderr = &stderr
	if err := run.Run(); err != nil {
		t.Fatalf("bash -c line: %v\nline=%s\nstderr=%s", err, cmd.Line, stderr.String())
	}
	if stdout.String() != argvOut {
		t.Fatalf("bash -c config != argv config\nline=%s\nver=%s\nbash-len=%d argv-len=%d", cmd.Line, ver, len(stdout.String()), len(argvOut))
	}
	writeEvidence(t, "line-argv-equivalent.txt", fmt.Sprintf("version=%s\nline=%s\nbyte-identical=true\nbytes=%d\n", ver, cmd.Line, len(argvOut)))
}

func runArgv(ctx context.Context, argv []string) (stdout, version string, err error) {
	if len(argv) < 2 {
		return "", "", fmt.Errorf("short argv")
	}
	ver := exec.CommandContext(ctx, argv[0], "compose", "version")
	var vbuf bytes.Buffer
	ver.Stdout = &vbuf
	if err := ver.Run(); err != nil {
		return "", "", fmt.Errorf("compose version: %w", err)
	}
	version = strings.TrimSpace(strings.TrimPrefix(strings.SplitN(vbuf.String(), "\n", 2)[0], "Docker Compose version "))
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		return stdoutBuf.String(), version, fmt.Errorf("%w: %s", err, stderrBuf.String())
	}
	return stdoutBuf.String(), version, nil
}

func internalModel(project string, files, envFiles, flagProfiles, environ []string) (explain.Input, error) {
	fp, err := redact.NewFingerprinter()
	if err != nil {
		return explain.Input{}, err
	}
	table, err := interp.Load(project, envFiles, project, environ, fp)
	if err != nil {
		return explain.Input{}, err
	}
	var overlay []*composeparse.Document
	var getter interp.Getter
	if table != nil {
		getter = table
	}
	for _, path := range files {
		raw, err := os.ReadFile(path)
		if err != nil {
			return explain.Input{}, err
		}
		doc, err := composeparse.Parse(discover.File{Path: path, Bytes: raw, Origin: "reproduction"})
		if err != nil {
			return explain.Input{}, err
		}
		expanded := include.Expand(doc, include.DiskLoad, getter)
		overlay = append(overlay, expanded.Docs...)
	}
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.DiskLoad, getter)
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(flagProfiles, environ)
	activated := profiles.Activate(merged, active)
	cen, err := containerenv.Resolve(merged, envsrc.HostMap(environ), getter)
	if err != nil {
		return explain.Input{}, err
	}
	return explain.Input{Merge: merged, Profiles: activated, Container: cen}, nil
}

func writeEvidence(t *testing.T, name, body string) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_REPRO_EVIDENCE_DIR")
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
