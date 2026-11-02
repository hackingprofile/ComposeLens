// SPDX-License-Identifier: Apache-2.0

package engineadapter

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"composelens/internal/digest"
	"composelens/internal/safety"

	"gopkg.in/yaml.v3"
)

func testdata(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func frozen() time.Time {
	return time.Date(2026, 8, 28, 4, 0, 0, 0, time.UTC)
}

func TestCaptureEngineAbsent(t *testing.T) {
	r := Runner{
		LookPath: func(string) (string, error) { return "", exec.ErrNotFound },
		Now:      frozen,
	}
	got := r.Capture(context.Background(), Request{ProjectDir: "proj", Files: []string{"compose.yaml"}})
	if got.State != StateEngineAbsent {
		t.Fatalf("state %s", got.State)
	}
	if got.ConfigStdout != "" {
		t.Fatalf("fabricated config: %q", got.ConfigStdout)
	}
	if got.Schema != Schema {
		t.Fatalf("schema %s", got.Schema)
	}
	writeCaptureJSON(t, "engine-absent.json", got)
}

func TestCaptureRecordedSample(t *testing.T) {
	ver := testdata(t, "version.txt")
	cfg := testdata(t, "config.yaml")
	r := Runner{
		LookPath: func(string) (string, error) { return "docker", nil },
		Now:      frozen,
		Exec: func(_ context.Context, name string, args []string) ExecResult {
			joined := name + " " + strings.Join(args, " ")
			if strings.Contains(joined, "version") {
				return ExecResult{Stdout: ver}
			}
			if strings.Contains(joined, "config") {
				return ExecResult{Stdout: cfg}
			}
			t.Fatalf("unexpected %s", joined)
			return ExecResult{}
		},
	}
	got := r.Capture(context.Background(), Request{
		ProjectDir: "proj",
		Files:      []string{"compose.yaml"},
	})
	if got.State != StateCaptured {
		t.Fatalf("state %s detail %s", got.State, got.Detail)
	}
	if got.Version != "v2.29.7" {
		t.Fatalf("version %q", got.Version)
	}
	if got.VersionCommand != "docker compose version" {
		t.Fatalf("ver cmd %q", got.VersionCommand)
	}
	if got.ConfigCommand != "docker compose --project-directory proj -f compose.yaml config" {
		t.Fatalf("cfg cmd %q", got.ConfigCommand)
	}
	if !strings.Contains(got.ConfigStdout, "COLOR: blue") {
		t.Fatalf("stdout %s", got.ConfigStdout)
	}
	if got.OutputDigest != digest.Bytes([]byte(got.ConfigStdout)) {
		t.Fatalf("digest mismatch")
	}
	if got.Timestamp != "2026-08-28T04:00:00Z" {
		t.Fatalf("ts %s", got.Timestamp)
	}
	writeCaptureJSON(t, "recorded-sample.json", got)
}

func TestCaptureEngineError(t *testing.T) {
	errBody := testdata(t, "error.txt")
	r := Runner{
		LookPath: func(string) (string, error) { return "docker", nil },
		Now:      frozen,
		Exec: func(_ context.Context, _ string, args []string) ExecResult {
			if len(args) > 0 && args[len(args)-1] == "config" {
				return ExecResult{Stderr: errBody, Exit: 1, Err: exec.ErrNotFound}
			}
			return ExecResult{Stdout: testdata(t, "version.txt")}
		},
	}
	got := r.Capture(context.Background(), Request{Files: []string{"missing.yaml"}})
	if got.State != StateEngineError {
		t.Fatalf("state %s", got.State)
	}
	if got.ConfigStdout != "" {
		t.Fatalf("must not keep failed config: %q", got.ConfigStdout)
	}
	if got.ExitCode != 1 {
		t.Fatalf("exit %d", got.ExitCode)
	}
}

func TestSecretRedactedInProcess(t *testing.T) {
	probe := "ghp_ComposeLensEngineProbe99"
	cfg := strings.Replace(testdata(t, "config.yaml"), "COLOR: blue", "COLOR: blue\n      API_TOKEN: "+probe, 1)
	r := Runner{
		LookPath: func(string) (string, error) { return "docker", nil },
		Now:      frozen,
		Exec: func(_ context.Context, _ string, args []string) ExecResult {
			if len(args) > 0 && args[len(args)-1] == "config" {
				return ExecResult{Stdout: cfg}
			}
			return ExecResult{Stdout: testdata(t, "version.txt")}
		},
	}
	got := r.Capture(context.Background(), Request{Files: []string{"compose.yaml"}})
	if got.State != StateCaptured {
		t.Fatalf("state %s detail %s", got.State, got.Detail)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), probe) || strings.Contains(got.ConfigStdout, probe) {
		t.Fatal("probe leaked into capture")
	}
	if !strings.Contains(got.ConfigStdout, redacted) {
		t.Fatalf("expected redaction, got %s", got.ConfigStdout)
	}
	if err := safety.Guard(raw, []string{probe}); err != nil {
		t.Fatal(err)
	}
	writeCaptureJSON(t, "secret-redacted-capture.json", got)
}

func TestCaptureEngineOutputOverCap(t *testing.T) {
	bound := safety.NewParseError(safety.CodeEngineOutputTooLarge, "", "engine output exceeds declared bound")
	r := Runner{
		LookPath: func(string) (string, error) { return "docker", nil },
		Now:      frozen,
		Exec: func(_ context.Context, _ string, args []string) ExecResult {
			if len(args) > 0 && args[len(args)-1] == "config" {
				return ExecResult{Overflow: true, Err: bound}
			}
			return ExecResult{Stdout: testdata(t, "version.txt")}
		},
	}
	got := r.Capture(context.Background(), Request{Files: []string{"compose.yaml"}})
	if got.ConfigStdout != "" || got.ConfigStderr != "" {
		t.Fatalf("must not retain over-cap output: %+v", got)
	}
	if !safety.IsResourceBound(got.Err) || safety.CodeOf(got.Err) != safety.CodeEngineOutputTooLarge {
		t.Fatalf("err=%v state=%s detail=%s", got.Err, got.State, got.Detail)
	}
	if got.State != StateEngineError {
		t.Fatalf("state %s", got.State)
	}
}

func TestUnsupportedVerb(t *testing.T) {
	got := Unsupported("up")
	if got.State != StateUnsupported {
		t.Fatalf("state %s", got.State)
	}
	if got.ConfigStdout != "" {
		t.Fatalf("fabricated %q", got.ConfigStdout)
	}
}

func TestDefaultRunnerThisMachineAbsentOrTyped(t *testing.T) {
	got := DefaultRunner().Capture(context.Background(), Request{
		ProjectDir: t.TempDir(),
		Files:      []string{"compose.yaml"},
	})
	switch got.State {
	case StateEngineAbsent, StateEngineError:
		if got.ConfigStdout != "" {
			t.Fatalf("no fabricated config on %s: %q", got.State, got.ConfigStdout)
		}
	case StateCaptured:
		t.Fatal("empty missing compose.yaml must not capture a fabricated model")
	default:
		t.Fatalf("state %s", got.State)
	}
	_, dockerErr := exec.LookPath("docker")
	_, composeErr := exec.LookPath("docker-compose")
	if dockerErr != nil && composeErr != nil {
		if got.State != StateEngineAbsent {
			t.Fatalf("compose CLI missing on PATH but state=%s", got.State)
		}
	}
	writeCaptureJSON(t, "detected-engine.json", got)
}

func TestLiveDockerPresenceIsRecorded(t *testing.T) {
	_, err := exec.LookPath("docker")
	if err == nil {
		t.Log("docker present; live capture is not claimed as a CI result")
		return
	}
	t.Log("docker absent; live engine capture skipped")
}

func writeCaptureJSON(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_ENGINEADAPTER_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), append(raw, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A token-shaped version string is not retained as the engine version.
func TestCaptureRejectsTokenShapedVersion(t *testing.T) {
	tok := "ghp_" + strings.Repeat("a", 30)
	r := Runner{
		LookPath: func(string) (string, error) { return "docker", nil },
		Exec: func(_ context.Context, _ string, args []string) ExecResult {
			if args[len(args)-1] == "version" {
				return ExecResult{Stdout: "Docker Compose version " + tok + "\n"}
			}
			return ExecResult{Stdout: "services:\n  web:\n    image: alpine:3.21\n"}
		},
		Now: frozen,
	}
	got := r.Capture(context.Background(), Request{ProjectDir: "proj", Files: []string{"compose.yaml"}})
	raw, _ := json.Marshal(got)
	if strings.Contains(string(raw), tok) || strings.Contains(got.Version, tok) {
		t.Fatalf("token retained: version=%q", got.Version)
	}
}

// Redacting engine YAML never turns valid YAML into invalid YAML,
// even when a withheld value is the first word of a wrapped scalar.
func TestRedactionNeverCorruptsEngineYAML(t *testing.T) {
	raw := "services:\n  web:\n    image: alpine\n    volumes:\n      - type: bind\n        source: aB3kL9xQ2mN8pR4t~V6wY1zC5dF7gH0jK\n          my data\n        target: /in\n"
	var probe any
	if err := yaml.Unmarshal([]byte(raw), &probe); err != nil {
		t.Fatalf("fixture must be valid YAML: %v", err)
	}
	out, secrets := RedactEngineOutput(raw)
	if len(secrets) == 0 || strings.Contains(out, "aB3kL9xQ2mN8pR4t~V6wY1zC5dF7gH0jK") {
		t.Fatalf("secret-shaped value not withheld: %q", out)
	}
	if err := yaml.Unmarshal([]byte(out), &probe); err != nil {
		t.Fatalf("redaction corrupted engine YAML: %v\n%s", err, out)
	}
	// An ordinary long path stays byte for byte.
	plain := "services:\n  web:\n    volumes:\n      - type: bind\n        source: " + `C:\Users\dev\AppData\Local\Temp\project_snapshot_12345678_4b7d2e9c\clean\fixtures\platform\paths-spaces\my` + "\n          data\n        target: /in\n"
	if got, s := RedactEngineOutput(plain); got != plain || len(s) != 0 {
		t.Fatalf("ordinary path changed: %q (%d withheld)", got, len(s))
	}
}
