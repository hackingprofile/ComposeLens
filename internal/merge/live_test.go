// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/evidence"
	"composelens/internal/testenv"
)

func TestLiveSequenceMergeMatchesEngine(t *testing.T) {
	testenv.RequireDocker(t)
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "examples", "sequence-merge-lab")
	base := filepath.Join(dir, "compose.yaml")
	over := filepath.Join(dir, "overlay.yaml")
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "compose", "--project-directory", dir, "-f", base, "-f", over, "config", "--no-interpolate")
	raw, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, raw)
	}
	engine := parseEngineService(t, raw, "web")
	fields := Documents([]*composeparse.Document{
		mustParseFile(t, base),
		mustParseFile(t, over),
	}, nil)
	m := byPath(fields)

	ports := m["services.web.ports"]
	if ports.Value != "[8080:80, 9090:80]" || ports.Action != ActionAppend || ports.Certainty != evidence.Proven {
		t.Fatalf("composelens ports %+v", ports)
	}
	if !engineHasPort(engine, "8080", 80) || !engineHasPort(engine, "9090", 80) {
		t.Fatalf("engine missing both ports: %#v", engine["ports"])
	}

	dns := m["services.web.dns"]
	if dns.Value != "[1.1.1.1, 8.8.8.8]" || dns.Action != ActionAppend {
		t.Fatalf("composelens dns %+v", dns)
	}
	if !engineHasSeq(engine, "dns", "1.1.1.1") || !engineHasSeq(engine, "dns", "8.8.8.8") {
		t.Fatalf("engine dns %#v", engine["dns"])
	}

	command := m["services.web.command"]
	if command.Value != "[echo, over]" || command.Action != ActionReplace {
		t.Fatalf("composelens command %+v", command)
	}
	if engineHasSeq(engine, "command", "base") {
		t.Fatalf("engine command still has base: %#v", engine["command"])
	}
	if !engineHasSeq(engine, "command", "over") {
		t.Fatalf("engine command %#v", engine["command"])
	}

	vols := m["services.web.volumes"]
	if vols.Value != "[./b:/data]" || vols.Action != ActionAppend {
		t.Fatalf("composelens volumes %+v", vols)
	}
	if !engineVolumeTarget(engine, "/data", "b") {
		t.Fatalf("engine volumes %#v", engine["volumes"])
	}

	dumpLiveEvidence(t, string(raw), m)
}

func TestLiveDriveLetterVolumeOverlayMatrix(t *testing.T) {
	testenv.RequireDocker(t)
	cases := []struct {
		name    string
		base    string
		over    string
		wantSrc string
		wantTgt string
		count   int
		keepA   bool
	}{
		{
			name:    "drive-same-target",
			base:    "services:\n  web:\n    image: alpine\n    volumes:\n      - 'C:\\Alpha:/data'\n",
			over:    "services:\n  web:\n    volumes:\n      - 'D:\\Beta:/data'\n",
			wantSrc: "Beta",
			wantTgt: "/data",
			count:   1,
		},
		{
			name:  "drive-different-target",
			base:  "services:\n  web:\n    image: alpine\n    volumes:\n      - 'C:\\Alpha:/data'\n",
			over:  "services:\n  web:\n    volumes:\n      - 'D:\\Beta:/other'\n",
			count: 2,
			keepA: true,
		},
		{
			name:    "relative-same-target",
			base:    "services:\n  web:\n    image: alpine\n    volumes:\n      - ./a:/data\n",
			over:    "services:\n  web:\n    volumes:\n      - ./b:/data\n",
			wantSrc: "b",
			wantTgt: "/data",
			count:   1,
		},
		{
			name:    "drive-mode-suffix",
			base:    "services:\n  web:\n    image: alpine\n    volumes:\n      - 'C:\\Alpha:/data:ro'\n",
			over:    "services:\n  web:\n    volumes:\n      - 'D:\\Beta:/data:rw'\n",
			wantSrc: "Beta",
			wantTgt: "/data",
			count:   1,
		},
		{
			name:    "long-syntax-same-target",
			base:    "services:\n  web:\n    image: alpine\n    volumes:\n      - type: bind\n        source: ./a\n        target: /data\n",
			over:    "services:\n  web:\n    volumes:\n      - type: bind\n        source: ./b\n        target: /data\n",
			wantSrc: "b",
			wantTgt: "/data",
			count:   1,
		},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			base := filepath.Join(dir, "compose.yaml")
			over := filepath.Join(dir, "overlay.yaml")
			if err := os.WriteFile(base, []byte(tc.base), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(over, []byte(tc.over), 0o644); err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, "docker", "compose", "--project-directory", dir, "-f", base, "-f", over, "config")
			raw, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("docker compose config: %v\n%s", err, raw)
			}
			engine := parseEngineService(t, raw, "web")
			n := engineVolumeCount(engine)
			if n != tc.count {
				t.Fatalf("engine volume count %d want %d\n%s", n, tc.count, raw)
			}
			fields := Documents([]*composeparse.Document{
				mustParseFile(t, base),
				mustParseFile(t, over),
			}, nil)
			got := byPath(fields)["services.web.volumes"].Value
			if tc.count == 1 {
				if !engineVolumeTarget(engine, tc.wantTgt, tc.wantSrc) {
					t.Fatalf("engine volumes %#v", engine["volumes"])
				}
				if strings.Contains(got, "Alpha") && tc.name != "drive-different-target" {
					t.Fatalf("composelens kept stale source %s", got)
				}
			}
			if tc.keepA && (!strings.Contains(got, "Alpha") || !strings.Contains(got, "Beta")) {
				t.Fatalf("composelens dropped a different-target volume %s", got)
			}
			if dirEvidence := os.Getenv("COMPOSELENS_VOLUME_OVERLAY_EVIDENCE_DIR"); dirEvidence != "" {
				if err := os.MkdirAll(dirEvidence, 0o755); err != nil {
					t.Fatal(err)
				}
				body := "case " + tc.name + "\nengine-count=" + strconv.Itoa(n) + "\ncomposelens=" + got + "\n" + string(raw)
				if err := os.WriteFile(filepath.Join(dirEvidence, tc.name+".txt"), []byte(body), 0o644); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func engineVolumeCount(svc map[string]any) int {
	list, _ := svc["volumes"].([]any)
	return len(list)
}

func mustParseFile(t *testing.T, path string) *composeparse.Document {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: path, Bytes: raw, Origin: "live"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func parseEngineService(t *testing.T, raw []byte, name string) map[string]any {
	t.Helper()
	var doc map[string]any
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	svcs, _ := doc["services"].(map[string]any)
	svc, _ := svcs[name].(map[string]any)
	if svc == nil {
		t.Fatalf("service %s missing in engine output", name)
	}
	return svc
}

func engineHasPort(svc map[string]any, published string, target int) bool {
	list, _ := svc["ports"].([]any)
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if stringify(m["published"]) == published && stringify(m["target"]) == strconv.Itoa(target) {
			return true
		}
	}
	return false
}

func engineHasSeq(svc map[string]any, field, want string) bool {
	list, _ := svc[field].([]any)
	for _, item := range list {
		if stringify(item) == want {
			return true
		}
	}
	return false
}

func engineVolumeTarget(svc map[string]any, target, sourceSubstr string) bool {
	list, _ := svc["volumes"].([]any)
	found := false
	for _, item := range list {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		if stringify(m["target"]) != target {
			continue
		}
		found = true
		src := stringify(m["source"])
		if !strings.Contains(strings.ReplaceAll(src, "\\", "/"), sourceSubstr) {
			return false
		}
	}
	return found && len(list) == 1
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	default:
		b, err := yaml.Marshal(v)
		if err != nil {
			return ""
		}
		return strings.TrimSpace(string(b))
	}
}

func dumpLiveEvidence(t *testing.T, engineYAML string, m map[string]Field) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_SEQMERGE_EVIDENCE_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	table := "field\trule\tcomposelens\tengine\n" +
		"ports\tappend+dedup distinct\t" + m["services.web.ports"].Value + "\tboth 8080:80 and 9090:80\n" +
		"dns\tappend\t" + m["services.web.dns"].Value + "\t1.1.1.1 then 8.8.8.8\n" +
		"command\tatomic-replace\t" + m["services.web.command"].Value + "\techo over only\n" +
		"volumes\tunique target\t" + m["services.web.volumes"].Value + "\tonly overlay ./b:/data\n"
	if err := os.WriteFile(filepath.Join(dir, "per-field-live.txt"), []byte(table), 0o644); err != nil {
		t.Fatal(err)
	}
	// Keep engine dump small: services.web only excerpt via the comparison table.
	_ = engineYAML
}
