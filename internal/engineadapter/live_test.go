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

	"composelens/internal/enginecap"
	"composelens/internal/safety"
)

func dockerAvailable() bool {
	if _, err := exec.LookPath("docker"); err == nil {
		return true
	}
	_, err := exec.LookPath("docker-compose")
	return err == nil
}

func TestLiveCaptureRepresentativeProjects(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker CLI not on PATH")
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	prec, err := filepath.Abs(filepath.Join(root, "examples", "precedence-lab"))
	if err != nil {
		t.Fatal(err)
	}
	merge, err := filepath.Abs(filepath.Join(root, "examples", "merge-lab"))
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		req  Request
	}{
		{name: "precedence-lab", req: Request{ProjectDir: prec}},
		{name: "merge-lab", req: Request{
			ProjectDir: merge,
			Files: []string{
				filepath.Join(merge, "compose.yaml"),
				filepath.Join(merge, "overlay.yaml"),
			},
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()
			got := DefaultRunner().Capture(ctx, tc.req)
			if got.State != StateCaptured {
				t.Fatalf("state=%s detail=%s stderr=%s", got.State, got.Detail, got.ConfigStderr)
			}
			if got.Version == "" || got.ConfigCommand == "" || got.OutputDigest == "" {
				t.Fatalf("incomplete capture %+v", got)
			}
			cap := enginecap.Assess(got.Version, got.State)
			if cap.Support != enginecap.SupportRecognized {
				t.Fatalf("support %s for version %s", cap.Support, got.Version)
			}
			dumpLive(t, tc.name+".json", liveEvidence{
				EngineVersion: got.Version,
				Command:       got.ConfigCommand,
				ExitCode:      got.ExitCode,
				Digest:        got.OutputDigest,
				Support:       cap.Support,
				Sample:        trimSample(got.ConfigStdout, 8),
			})
		})
	}
}

func TestLiveSecretKeyedValueRedacted(t *testing.T) {
	if !dockerAvailable() {
		t.Skip("docker CLI not on PATH")
	}
	probe := "ghp_ComposeLensCapProbe99"
	dir := t.TempDir()
	body := "services:\n  web:\n    image: alpine\n    environment:\n      API_TOKEN: " + probe + "\n      COLOR: blue\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	got := DefaultRunner().Capture(ctx, Request{ProjectDir: dir, Files: []string{filepath.Join(dir, "compose.yaml")}})
	if got.State != StateCaptured {
		t.Fatalf("state=%s detail=%s stderr=%s", got.State, got.Detail, got.ConfigStderr)
	}
	raw, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), probe) || strings.Contains(got.ConfigStdout, probe) {
		t.Fatal("live config leaked probe")
	}
	if !strings.Contains(got.ConfigStdout, "[redacted]") {
		t.Fatalf("expected redaction: %s", trimSample(got.ConfigStdout, 12))
	}
	if err := safety.Guard(raw, []string{probe}); err != nil {
		t.Fatal(err)
	}
	dumpLive(t, "secret-live.json", liveEvidence{
		EngineVersion: got.Version,
		Command:       got.ConfigCommand,
		ExitCode:      got.ExitCode,
		Digest:        got.OutputDigest,
		Sample:        trimSample(got.ConfigStdout, 8),
		Redacted:      true,
	})
}

type liveEvidence struct {
	EngineVersion string `json:"engineVersion"`
	Command       string `json:"command"`
	ExitCode      int    `json:"exitCode"`
	Digest        string `json:"digest"`
	Support       string `json:"support,omitempty"`
	Sample        string `json:"sample,omitempty"`
	Redacted      bool   `json:"redacted,omitempty"`
}

func trimSample(s string, lines int) string {
	parts := strings.Split(s, "\n")
	if len(parts) > lines {
		parts = parts[:lines]
	}
	return strings.Join(parts, "\n")
}

func dumpLive(t *testing.T, name string, v any) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_ENGINECAP_EVIDENCE_DIR")
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
