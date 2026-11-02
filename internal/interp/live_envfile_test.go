// SPDX-License-Identifier: Apache-2.0

package interp

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

	"composelens/internal/redact"
	"composelens/internal/safety"
	"composelens/internal/testenv"
)

func TestLiveEnvFileReplacesProjectDotenv(t *testing.T) {
	testenv.RequireDocker(t)
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:${TAG}\n    hostname: ${HOSTV}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TAG=1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("HOSTV=repro-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	noFlag, ver, err := runComposeConfig(ctx, dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(noFlag, "nginx:1.25") {
		t.Fatalf("engine without --env-file want nginx:1.25\n%s", noFlag)
	}
	clean := interpolationTestEnv(nil)
	none, err := Load(dir, nil, dir, clean, fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := none.Get("TAG"); !ok || v != "1.25" {
		t.Fatalf("no --env-file ComposeLens TAG=%q ok=%v", v, ok)
	}

	withFlag, _, err := runComposeConfig(ctx, dir, []string{extra})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withFlag, "nginx:1.25") {
		t.Fatalf("engine with --env-file must drop TAG from .env\n%s", withFlag)
	}
	if !strings.Contains(withFlag, "nginx:") || !strings.Contains(withFlag, "repro-host") {
		t.Fatalf("engine with --env-file want nginx: + repro-host\n%s", withFlag)
	}
	with, err := Load(dir, []string{extra}, dir, clean, fp)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := with.Get("TAG"); ok {
		t.Fatal("ComposeLens still loaded .env TAG under --env-file (additive)")
	}
	if v, ok, _ := with.Get("HOSTV"); !ok || v != "repro-host" {
		t.Fatalf("ComposeLens HOSTV=%q ok=%v", v, ok)
	}

	shellOut, _, err := runComposeConfigEnv(ctx, dir, []string{extra}, []string{"TAG=from-shell"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(shellOut, "nginx:from-shell") {
		t.Fatalf("engine shell TAG\n%s", shellOut)
	}
	shell, err := Load(dir, []string{extra}, dir, interpolationTestEnv([]string{"TAG=from-shell"}), fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, src := shell.Get("TAG"); !ok || v != "from-shell" || src.Stage != "host-shell" {
		t.Fatalf("shell TAG %+v %s", src, v)
	}

	writeEnvfileEvidence(t, "11-after-live.txt", fmt.Sprintf(
		"compose-plugin=%s\nengine-no-env-file-contains-nginx:1.25=true\nengine-with-env-file-drops-TAG=true\nengine-with-env-file-hostname=repro-host\ncomposelens-no-env-file-TAG=1.25\ncomposelens-with-env-file-TAG-dropped=true\ncomposelens-with-env-file-HOSTV=repro-host\nhost-shell-highest=true\n",
		ver,
	))
}

func interpolationTestEnv(extra []string) []string {
	// Drop interpolation keys that live tests assert so host process values
	// cannot change one side of the Docker/ComposeLens comparison.
	drop := map[string]struct{}{
		"TAG":               {},
		"HOSTV":             {},
		"COLOR":             {},
		"COMPOSE_ENV_FILES": {},
		"COMPOSE_FILE":      {},
		"COMPOSE_PROFILES":  {},
	}
	var out []string
	for _, kv := range os.Environ() {
		i := strings.IndexByte(kv, '=')
		if i <= 0 {
			continue
		}
		if _, skip := drop[kv[:i]]; skip {
			continue
		}
		out = append(out, kv)
	}
	return append(out, extra...)
}

func runComposeConfig(ctx context.Context, dir string, envFiles []string) (stdout, version string, err error) {
	return runComposeConfigEnv(ctx, dir, envFiles, nil)
}

func runComposeConfigEnv(ctx context.Context, dir string, envFiles, extraEnv []string) (stdout, version string, err error) {
	ver := exec.CommandContext(ctx, "docker", "compose", "version")
	var vbuf bytes.Buffer
	ver.Stdout = &vbuf
	if err := ver.Run(); err != nil {
		return "", "", fmt.Errorf("compose version: %w", err)
	}
	version = strings.TrimSpace(strings.TrimPrefix(strings.SplitN(vbuf.String(), "\n", 2)[0], "Docker Compose version "))
	args := []string{"compose", "--project-directory", dir}
	for _, f := range envFiles {
		args = append(args, "--env-file", f)
	}
	args = append(args, "config")
	cmd := exec.CommandContext(ctx, "docker", args...)
	cmd.Env = interpolationTestEnv(extraEnv)
	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf
	if err := cmd.Run(); err != nil {
		return stdoutBuf.String(), version, fmt.Errorf("%w: %s", err, stderrBuf.String())
	}
	return stdoutBuf.String(), version, nil
}

func writeEnvfileEvidence(t *testing.T, name, body string) {
	t.Helper()
	dir := os.Getenv("COMPOSELENS_ENVFILE_EVIDENCE_DIR")
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

func TestLiveOversizedUnselectedDotenvDoesNotBlock(t *testing.T) {
	testenv.RequireDocker(t)
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: nginx:${TAG}\n    hostname: ${HOSTV}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	big := append([]byte("TAG=1.25\nHOSTV=dotenv-host\n"), bytes.Repeat([]byte("n"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, ".env"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("HOSTV=repro-host\nTAG=selected\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	engineOut, _, err := runComposeConfig(ctx, dir, []string{extra})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(engineOut, "nginx:1.25") || strings.Contains(engineOut, "dotenv-host") {
		t.Fatalf("engine used unselected .env\n%s", engineOut)
	}
	if !strings.Contains(engineOut, "nginx:selected") || !strings.Contains(engineOut, "repro-host") {
		t.Fatalf("engine missing selected values\n%s", engineOut)
	}
	tbl, err := Load(dir, []string{extra}, dir, interpolationTestEnv(nil), fp)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok, _ := tbl.Get("TAG"); !ok || v != "selected" {
		t.Fatalf("TAG=%q ok=%v", v, ok)
	}
	if v, ok, _ := tbl.Get("HOSTV"); !ok || v != "repro-host" {
		t.Fatalf("HOSTV=%q ok=%v", v, ok)
	}
	if _, err := Load(dir, nil, dir, interpolationTestEnv(nil), fp); err == nil {
		t.Fatal("selected oversized .env must fail")
	}
}

func TestLiveComposeEnvFilesMatchEngine(t *testing.T) {
	testenv.RequireDocker(t)
	dir := t.TempDir()
	compose := "services:\n  web:\n    image: alpine:${TAG:-3.21.3}\n    hostname: ${HOSTV:-none}\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	a := filepath.Join(dir, "a.env")
	b := filepath.Join(dir, "b.env")
	pre := filepath.Join(dir, "pre.env")
	explicit := filepath.Join(dir, "explicit.env")
	left := filepath.Join(dir, "left.env")
	right := filepath.Join(dir, "right.env")
	missing := filepath.Join(dir, "missing.env")
	if err := os.WriteFile(a, []byte("TAG=from-a\nHOSTV=host-a\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("TAG=from-b\nHOSTV=host-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pre, []byte("TAG=3.20\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(explicit, []byte("HOSTV=explicit-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(left, []byte("TAG=left\nHOSTV=left-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(right, []byte("TAG=right\nHOSTV=right-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	assertMatch := func(name, engineOut string, envFiles []string, environ []string, wantImage, wantHost string) {
		t.Helper()
		if !strings.Contains(engineOut, wantImage) || !strings.Contains(engineOut, wantHost) {
			t.Fatalf("%s engine missing %s / %s\n%s", name, wantImage, wantHost, engineOut)
		}
		tbl, err := Load(dir, envFiles, dir, interpolationTestEnv(environ), fp)
		if err != nil {
			t.Fatalf("%s Load: %v", name, err)
		}
		img := Substitute("alpine:${TAG:-3.21.3}", tbl)
		host := Substitute("${HOSTV:-none}", tbl)
		if img.Resolved != wantImage || host.Resolved != wantHost {
			t.Fatalf("%s ComposeLens image=%q host=%q want %s / %s", name, img.Resolved, host.Resolved, wantImage, wantHost)
		}
	}

	commaEnv := []string{"COMPOSE_ENV_FILES=" + a + "," + b}
	commaOut, _, err := runComposeConfigEnv(ctx, dir, nil, commaEnv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch("comma-list", commaOut, nil, commaEnv, "alpine:from-b", "host-b")

	overrideEnv := []string{"COMPOSE_ENV_FILES=" + missing}
	overOut, _, err := runComposeConfigEnv(ctx, dir, []string{explicit}, overrideEnv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch("explicit-overrides-missing-predefined", overOut, []string{explicit}, overrideEnv, "alpine:3.21.3", "explicit-host")

	preEnv := []string{"COMPOSE_ENV_FILES=" + pre}
	preOut, _, err := runComposeConfigEnv(ctx, dir, []string{explicit}, preEnv)
	if err != nil {
		t.Fatal(err)
	}
	assertMatch("explicit-drops-predefined-TAG", preOut, []string{explicit}, preEnv, "alpine:3.21.3", "explicit-host")

	leftOut, _, err := runComposeConfig(ctx, dir, []string{left})
	if err != nil {
		t.Fatal(err)
	}
	rightOut, _, err := runComposeConfig(ctx, dir, []string{right})
	if err != nil {
		t.Fatal(err)
	}
	assertMatch("diff-left", leftOut, []string{left}, commaEnv, "alpine:left", "left-host")
	assertMatch("diff-right", rightOut, []string{right}, commaEnv, "alpine:right", "right-host")
}
