// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"composelens/internal/engineadapter"
	"composelens/internal/exitcode"
)

type recordingEngine struct {
	mu    sync.Mutex
	calls [][]string
}

func (r *recordingEngine) runner() engineadapter.Runner {
	return engineadapter.Runner{
		LookPath: func(string) (string, error) { return "docker", nil },
		Exec: func(_ context.Context, name string, args []string) engineadapter.ExecResult {
			r.mu.Lock()
			r.calls = append(r.calls, append([]string{name}, args...))
			r.mu.Unlock()
			if args[len(args)-1] == "version" {
				return engineadapter.ExecResult{Stdout: "Docker Compose version v5.4.0\n"}
			}
			return engineadapter.ExecResult{Stdout: "services:\n  web:\n    image: alpine:3.21\n"}
		},
	}
}

func (r *recordingEngine) configCalls() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	n := 0
	for _, c := range r.calls {
		if c[len(c)-1] == "config" {
			n++
		}
	}
	return n
}

func differentialState(t *testing.T, raw []byte, inReport bool) (string, string) {
	t.Helper()
	var d struct {
		EngineState string `json:"engineState"`
		SkipReason  string `json:"engineSkipReason"`
	}
	if inReport {
		var rep struct {
			Differential json.RawMessage `json:"differential"`
		}
		if err := json.Unmarshal(raw, &rep); err != nil {
			t.Fatal(err)
		}
		raw = rep.Differential
	}
	if err := json.Unmarshal(raw, &d); err != nil {
		t.Fatal(err)
	}
	return d.EngineState, d.SkipReason
}

// report --no-engine never invokes Docker; its differential
// section is a typed skip.
func TestReportNoEngineNeverInvokesDocker(t *testing.T) {
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n"})
	for _, format := range []string{"--json", "--html"} {
		rec := &recordingEngine{}
		rt, out, errb := reportRT(dir)
		rt.EngineRunner = rec.runner
		code := rt.Run([]string{"report", format, "--no-engine", "--project-directory", dir})
		if code != exitcode.OK || len(rec.calls) != 0 {
			t.Fatalf("%s: code=%d docker calls=%v err=%s", format, code, rec.calls, errb.String())
		}
		if format == "--json" {
			if st, why := differentialState(t, out.Bytes(), true); st != engineadapter.StateSkipped || !strings.Contains(why, "--no-engine") {
				t.Fatalf("state=%q reason=%q", st, why)
			}
		}
	}
	rt, _, _ := reportRT(dir)
	if code := rt.Run([]string{"inspect", "--no-engine", "--project-directory", dir}); code != exitcode.Usage {
		t.Fatalf("--no-engine outside report: code=%d", code)
	}
}

// A remote include (OCI, Git, HTTP) skips the engine capture
// with a typed reason unless --allow-network is given.
func TestRemoteIncludeSkipsCaptureUnlessAllowed(t *testing.T) {
	for _, ref := range []string{"oci://localhost:8766/solar/model:demo", "https://example.test/repo.git", "git@example.test:org/repo.git"} {
		dir := writeProbeProject(t, map[string]string{"compose.yaml": "include:\n  - " + ref + "\nservices:\n  web:\n    image: alpine:3.21\n"})
		for _, cmd := range [][]string{{"report", "--json"}, {"differential", "--json"}} {
			rec := &recordingEngine{}
			rt, out, errb := reportRT(dir)
			rt.EngineRunner = rec.runner
			code := rt.Run(append(append([]string{}, cmd...), "--project-directory", dir))
			if code != exitcode.OK || rec.configCalls() != 0 {
				t.Fatalf("%s %s: code=%d config calls=%d err=%s", ref, cmd[0], code, rec.configCalls(), errb.String())
			}
			st, why := differentialState(t, out.Bytes(), cmd[0] == "report")
			if st != engineadapter.StateSkipped || !strings.Contains(why, "remote include") {
				t.Fatalf("%s %s: state=%q reason=%q", ref, cmd[0], st, why)
			}
			rec = &recordingEngine{}
			rt, _, errb = reportRT(dir)
			rt.EngineRunner = rec.runner
			if code := rt.Run(append(append([]string{}, cmd...), "--allow-network", "--project-directory", dir)); code != exitcode.OK || rec.configCalls() != 1 {
				t.Fatalf("%s %s --allow-network: code=%d config calls=%d err=%s", ref, cmd[0], code, rec.configCalls(), errb.String())
			}
		}
	}
}
