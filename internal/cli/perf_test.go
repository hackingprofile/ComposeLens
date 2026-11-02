// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/testenv"
)

func TestCLIDifferentialLiveSequenceMerge(t *testing.T) {
	testenv.RequireDocker(t)
	root := chdirRoot(t)
	dir := filepath.Join("examples", "sequence-merge-lab")
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: engine.Detect}
	code := rt.Run([]string{"differential", "--json", "--project-directory", dir, "--file", filepath.Join(dir, "compose.yaml"), "--file", filepath.Join(dir, "overlay.yaml")})
	if code != 0 {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if !strings.Contains(out.String(), `"schema": "composelens.differential.v0"`) {
		t.Fatalf("%s", out.String())
	}
	if strings.Contains(out.String(), "demo-inline") {
		t.Fatal("secret")
	}
}

func TestLargeProjectStaysInteractive(t *testing.T) {
	root := chdirRoot(t)
	dir := filepath.Join("fixtures", "perf", "large")
	if _, err := os.Stat(filepath.Join(root, dir, "compose.yaml")); err != nil {
		t.Fatal(err)
	}
	// The documented interactivity bound is for a normal build. The race
	// detector slows code several-fold, so under -race the test checks a
	// proportionally larger bound and still catches a runaway.
	budget := 2 * time.Second
	if raceEnabled {
		budget *= 10
	}
	detect := func() engine.Info { return engine.Info{State: evidence.Absent} }
	for _, args := range [][]string{
		{"check", "--json", "--project-directory", dir},
		{"report", "--json", "--project-directory", dir},
		{"report", "--html", "--project-directory", dir},
	} {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: detect}
		start := time.Now()
		code := rt.Run(args)
		elapsed := time.Since(start)
		if code != 0 {
			t.Fatalf("%v code=%d err=%s", args, code, errb.String())
		}
		if elapsed > budget {
			t.Fatalf("%v took %s want <%s", args, elapsed, budget)
		}
		t.Logf("%v %s", args, elapsed)
	}
}

func TestOverBudgetFileTooLargeTypedExit(t *testing.T) {
	root := chdirRoot(t)
	dir := t.TempDir()
	huge := append([]byte("services:\n  web:\n    image: alpine\n"), bytes.Repeat([]byte("#"), 1<<20)...)
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: func() engine.Info { return engine.Info{State: evidence.Absent} }}
	code := rt.Run([]string{"check", "--json", "--project-directory", dir})
	if code != exitcode.Input {
		t.Fatalf("code=%d err=%s", code, errb.String())
	}
	if out.Len() != 0 {
		t.Fatalf("analysis stdout: %s", out.String())
	}
	if !strings.Contains(errb.String(), "input-too-large") && !strings.Contains(errb.String(), "input-total-too-large") {
		t.Fatalf("stderr=%s", errb.String())
	}
	if strings.Contains(errb.String(), "CHK01") {
		t.Fatal("analysis ran")
	}
}

func BenchmarkCheckLarge(b *testing.B) {
	root := benchRoot(b)
	dir := filepath.Join("fixtures", "perf", "large")
	detect := func() engine.Info { return engine.Info{State: evidence.Absent} }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: detect}
		if code := rt.Run([]string{"check", "--json", "--project-directory", dir}); code != 0 {
			b.Fatalf("code=%d %s", code, errb.String())
		}
	}
}

func BenchmarkReportJSONLarge(b *testing.B) {
	root := benchRoot(b)
	dir := filepath.Join("fixtures", "perf", "large")
	detect := func() engine.Info { return engine.Info{State: evidence.Absent} }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: detect}
		if code := rt.Run([]string{"report", "--json", "--project-directory", dir}); code != 0 {
			b.Fatalf("code=%d %s", code, errb.String())
		}
	}
}

func BenchmarkReportHTMLLarge(b *testing.B) {
	root := benchRoot(b)
	dir := filepath.Join("fixtures", "perf", "large")
	detect := func() engine.Info { return engine.Info{State: evidence.Absent} }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: detect}
		if code := rt.Run([]string{"report", "--html", "--project-directory", dir}); code != 0 {
			b.Fatalf("code=%d %s", code, errb.String())
		}
	}
}

func BenchmarkInspectParseMergeInterpLarge(b *testing.B) {
	root := benchRoot(b)
	dir := filepath.Join("fixtures", "perf", "large")
	detect := func() engine.Info { return engine.Info{State: evidence.Absent} }
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		var out, errb bytes.Buffer
		rt := Runtime{Stdout: &out, Stderr: &errb, Cwd: root, Detect: detect}
		if code := rt.Run([]string{"inspect", "--json", "--project-directory", dir}); code != 0 {
			b.Fatalf("code=%d %s", code, errb.String())
		}
	}
}

func benchRoot(b *testing.B) string {
	b.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		b.Fatal("caller")
	}
	root := filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
	old, err := os.Getwd()
	if err != nil {
		b.Fatal(err)
	}
	if err := os.Chdir(root); err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = os.Chdir(old) })
	return root
}
