// SPDX-License-Identifier: Apache-2.0

package normalize

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/evidence"
	"composelens/internal/merge"
	"composelens/internal/redact"
)

func loadNorm(t *testing.T, rel string) Model {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "normalize", rel, "compose.yaml")
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return FromMerge(merge.Documents([]*composeparse.Document{d}, nil))
}

func webOf(t *testing.T, m Model) Service {
	t.Helper()
	s, ok := ServiceByName(m, "web")
	if !ok {
		t.Fatalf("missing web in %+v", m.Services)
	}
	return s
}

func TestPortsShortLongEqualAndUnequal(t *testing.T) {
	short := webOf(t, loadNorm(t, filepath.Join("ports", "short")))
	long := webOf(t, loadNorm(t, filepath.Join("ports", "long")))
	if !PortsEqual(short.Ports, long.Ports) {
		t.Fatalf("short=%q long=%q", DisplayPorts(short.Ports), DisplayPorts(long.Ports))
	}
	if DisplayPorts(short.Ports) != DisplayPorts(long.Ports) {
		t.Fatalf("canonical display short=%q long=%q", DisplayPorts(short.Ports), DisplayPorts(long.Ports))
	}
	if len(short.Ports) != 3 {
		t.Fatalf("want 3 ports, got %d", len(short.Ports))
	}
	if short.Ports[0].Provenance.Source == "" || long.Ports[0].Provenance.Source == "" {
		t.Fatal("provenance source dropped")
	}
	uneq := webOf(t, loadNorm(t, filepath.Join("ports", "unequal")))
	if PortsEqual(short.Ports[:1], uneq.Ports) {
		t.Fatalf("9000:8000 must not equal 8000:8000: %q", DisplayPorts(uneq.Ports))
	}
}

func TestPortsUnknownExtraNotEqual(t *testing.T) {
	long := webOf(t, loadNorm(t, filepath.Join("ports", "long")))
	extra := webOf(t, loadNorm(t, filepath.Join("ports", "unknown-extra")))
	if extra.Ports[0].Provenance.Certainty != evidence.Unknown {
		t.Fatalf("extra key should be unknown, got %+v", extra.Ports[0].Provenance)
	}
	if PortEqual(long.Ports[0], extra.Ports[0]) {
		t.Fatal("undocumented extra long-form key must not compare equal")
	}
}

func TestVolumesShortLongEqualAndUnequal(t *testing.T) {
	short := webOf(t, loadNorm(t, filepath.Join("volumes", "short")))
	long := webOf(t, loadNorm(t, filepath.Join("volumes", "long")))
	if !VolumesEqual(short.Volumes, long.Volumes) {
		t.Fatalf("short=%q long=%q", DisplayVolumes(short.Volumes), DisplayVolumes(long.Volumes))
	}
	if DisplayVolumes(short.Volumes) != DisplayVolumes(long.Volumes) {
		t.Fatalf("canonical display short=%q long=%q", DisplayVolumes(short.Volumes), DisplayVolumes(long.Volumes))
	}
	if short.Volumes[0].Type != "bind" || short.Volumes[1].Type != "volume" {
		t.Fatalf("types %+v", short.Volumes)
	}
	uneq := webOf(t, loadNorm(t, filepath.Join("volumes", "unequal")))
	if VolumeEqual(short.Volumes[0], uneq.Volumes[0]) {
		t.Fatal("rw bind must not equal ro bind")
	}
}

func TestVolumeShortWindowsDriveTarget(t *testing.T) {
	raw := "services:\n  web:\n    image: alpine\n    volumes:\n      - 'C:\\Alpha:/data:ro'\n"
	d, err := composeparse.Parse(discover.File{Path: "drive.yaml", Bytes: []byte(raw), Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	s := webOf(t, FromMerge(merge.Documents([]*composeparse.Document{d}, nil)))
	if len(s.Volumes) != 1 {
		t.Fatalf("vols %+v", s.Volumes)
	}
	v := s.Volumes[0]
	if v.Source != `C:\Alpha` || v.Target != "/data" || !v.ReadOnly || v.Type != "bind" {
		t.Fatalf("parsed %+v display=%q", v, DisplayVolume(v))
	}
}

func TestLabelsListMapEqualAndUnequal(t *testing.T) {
	list := webOf(t, loadNorm(t, filepath.Join("labels", "list")))
	mp := webOf(t, loadNorm(t, filepath.Join("labels", "map")))
	if !LabelsEqual(list.Labels, mp.Labels) {
		t.Fatalf("list=%q map=%q", DisplayLabels(list.Labels), DisplayLabels(mp.Labels))
	}
	if DisplayLabels(list.Labels) != DisplayLabels(mp.Labels) {
		t.Fatalf("canonical display list=%q map=%q", DisplayLabels(list.Labels), DisplayLabels(mp.Labels))
	}
	if DisplayLabels(list.Labels) != "app=web, com.example.role=front" {
		t.Fatalf("order-insensitive sorted display %q", DisplayLabels(list.Labels))
	}
	uneq := webOf(t, loadNorm(t, filepath.Join("labels", "unequal")))
	if LabelsEqual(list.Labels, uneq.Labels) {
		t.Fatal("app=api must not equal app=web")
	}
}

func TestCommandExecFormsEqualShellVsExecDistinct(t *testing.T) {
	flow := webOf(t, loadNorm(t, filepath.Join("command", "exec-flow")))
	block := webOf(t, loadNorm(t, filepath.Join("command", "exec-block")))
	if !CommandEqual(flow.Command, block.Command) {
		t.Fatalf("exec flow=%q block=%q", DisplayCommand(flow.Command), DisplayCommand(block.Command))
	}
	if !CommandEqual(flow.Entrypoint, block.Entrypoint) {
		t.Fatalf("entrypoint flow=%q block=%q", DisplayCommand(flow.Entrypoint), DisplayCommand(block.Entrypoint))
	}
	if DisplayCommand(flow.Command) != DisplayCommand(block.Command) {
		t.Fatalf("canonical command display flow=%q block=%q", DisplayCommand(flow.Command), DisplayCommand(block.Command))
	}
	shell := webOf(t, loadNorm(t, filepath.Join("command", "shell")))
	if CommandEqual(shell.Command, flow.Command) {
		t.Fatal("Compose shell form must not compare equal to exec form")
	}
	if CommandEqual(shell.Entrypoint, flow.Entrypoint) {
		t.Fatal("Compose shell entrypoint must not compare equal to exec form")
	}
	if shell.Command.Form != FormShell || flow.Command.Form != FormExec {
		t.Fatalf("forms shell=%s exec=%s", shell.Command.Form, flow.Command.Form)
	}
}

func TestHealthcheckStringEqualsCMDShellNotCMD(t *testing.T) {
	str := webOf(t, loadNorm(t, filepath.Join("healthcheck", "string")))
	sh := webOf(t, loadNorm(t, filepath.Join("healthcheck", "cmd-shell")))
	cmd := webOf(t, loadNorm(t, filepath.Join("healthcheck", "cmd")))
	if !HealthcheckEqual(str.Healthcheck, sh.Healthcheck) {
		t.Fatalf("string=%q cmd-shell=%q", DisplayHealthcheck(str.Healthcheck), DisplayHealthcheck(sh.Healthcheck))
	}
	if DisplayHealthcheck(str.Healthcheck) != DisplayHealthcheck(sh.Healthcheck) {
		t.Fatalf("canonical display string=%q cmd-shell=%q", DisplayHealthcheck(str.Healthcheck), DisplayHealthcheck(sh.Healthcheck))
	}
	if HealthcheckEqual(str.Healthcheck, cmd.Healthcheck) {
		t.Fatal("CMD-SHELL/string must not equal CMD exec form")
	}
	if str.Healthcheck.Kind != KindCMDShell || cmd.Healthcheck.Kind != KindCMD {
		t.Fatalf("kinds string=%s cmd=%s", str.Healthcheck.Kind, cmd.Healthcheck.Kind)
	}
}

func TestEnvironmentNotDuplicated(t *testing.T) {
	p := filepath.Join(t.TempDir(), "compose.yaml")
	body := "services:\n  web:\n    image: alpine\n    environment:\n      COLOR: teal\n    env_file:\n      - extra.env\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	fields := merge.Documents([]*composeparse.Document{d}, nil)
	m := FromMerge(fields)
	s := webOf(t, m)
	if len(s.Ports)+len(s.Volumes)+len(s.Labels.Pairs) != 0 || s.Command != nil || s.Healthcheck != nil {
		t.Fatalf("environment-only service should not grow dual-form fields: %+v", s)
	}
	hasEnv := false
	for _, f := range fields {
		if strings.Contains(f.Path, ".environment") || strings.Contains(f.Path, ".env_file") {
			hasEnv = true
		}
	}
	if !hasEnv {
		t.Fatal("merge still models environment; normalize must not swallow it")
	}
}

func TestSecretThroughNormalizationRedactedInProcess(t *testing.T) {
	token := "ghp_ComposeLensNormProbe99xxxxxxxx"
	if !redact.LooksLikeSecret(token) {
		t.Fatal("probe token must be classified secret")
	}
	dir := t.TempDir()
	body := "" +
		"services:\n" +
		"  web:\n" +
		"    image: alpine\n" +
		"    labels:\n" +
		"      - API_TOKEN=" + token + "\n" +
		"    command: echo " + token + "\n"
	p := filepath.Join(dir, "compose.yaml")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	m := FromMerge(merge.Documents([]*composeparse.Document{d}, nil))
	s := webOf(t, m)
	if len(s.Labels.Pairs) != 1 || !s.Labels.Pairs[0].Provenance.Secret {
		t.Fatalf("label secret flag %+v", s.Labels)
	}
	if s.Command == nil || !s.Command.Provenance.Secret {
		t.Fatalf("command secret flag %+v", s.Command)
	}
	frags := SecretFragments(m)
	found := false
	for _, f := range frags {
		if strings.Contains(f, token) {
			found = true
		}
	}
	if !found {
		t.Fatalf("SecretFragments must include probe token for fail-closed, got %v", frags)
	}
	disp := DisplayLabels(s.Labels) + DisplayCommand(s.Command)
	if !strings.Contains(disp, token) {
		t.Fatal("canonical display still holds the value internally; redaction is an output concern")
	}
}

func TestProvenanceCopiedFromMerge(t *testing.T) {
	m := loadNorm(t, filepath.Join("ports", "short"))
	s := webOf(t, m)
	if s.Ports[0].Provenance.Source == "" || s.Ports[0].Provenance.Line == 0 {
		t.Fatalf("want winner+line, got %+v", s.Ports[0].Provenance)
	}
	if s.Ports[0].Provenance.Certainty != evidence.Proven {
		t.Fatalf("certainty %+v", s.Ports[0].Provenance)
	}
}
