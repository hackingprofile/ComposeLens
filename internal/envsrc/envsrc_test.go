// SPDX-License-Identifier: Apache-2.0

package envsrc

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/redact"
	"composelens/internal/safety"
)

func mustFP(t *testing.T) *redact.Fingerprinter {
	t.Helper()
	fp, err := redact.NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	return fp
}

func TestCollectLabelsSourcesAndRedacts(t *testing.T) {
	dir := t.TempDir()
	dotenv := "APP_ENV=dev\nAPI_TOKEN=runtime-only-secret-value-aaaa\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte(dotenv), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("APP_ENV=staging\nFEATURE=on\nAPI_TOKEN=runtime-only-secret-value-aaaa\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	environ := []string{"COMPOSE_PROJECT_NAME=demo", "UNRELATED_SECRET=should-not-be-collected", "PATH=/nope"}
	got, err := Collect(dir, []string{extra}, dir, environ, mustFP(t))
	if err != nil {
		t.Fatal(err)
	}
	var host, proj, file, token, leaked bool
	for _, b := range got {
		switch {
		case b.Key == "COMPOSE_PROJECT_NAME" && b.Stage == "host-shell":
			host = true
			if b.Line != 0 || b.Path != "" {
				t.Fatalf("host source coords: %+v", b)
			}
		case b.Key == "UNRELATED_SECRET", b.Key == "PATH":
			leaked = true
		case b.Key == "APP_ENV" && b.Stage == "project-env":
			t.Fatalf("unselected project .env must not be collected: %+v", b)
		case b.Key == "APP_ENV" && b.Stage == "env-file" && b.Line == 1:
			file = true
			proj = true
		case b.Key == "API_TOKEN":
			token = true
			if !b.Secret || b.Fingerprint == "" {
				t.Fatalf("token not redacted/fingerprinted: %+v", b)
			}
		}
	}
	if !host || !proj || !file || !token {
		t.Fatalf("missing labels host=%v file=%v token=%v bindings=%d", host, file, token, len(got))
	}
	path, ok := UnappliedProjectEnv(dir, []string{extra}, dir, environ)
	if !ok || path == "" {
		t.Fatal("unselected .env must still be observable")
	}
	if leaked {
		t.Fatal("host allowlist violated")
	}
	secrets := SecretValues(got)
	if len(secrets) != 1 || secrets[0] != "runtime-only-secret-value-aaaa" {
		t.Fatalf("secrets=%v", secrets)
	}
}

func TestCollectURICredentialsAndSameRunFingerprints(t *testing.T) {
	dir := t.TempDir()
	body := "" +
		"DATABASE_URL=postgres://demo-user:synthetic-password@db.internal/app\n" +
		"SAFE_URL=postgres://localhost:5432/app\n" +
		"HOOK=https://api.example.invalid/hook?token=synthetic-token-value\n" +
		"SHARED=same-run-value\n"
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("SHARED=same-run-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	extra2 := filepath.Join(dir, "extra2.env")
	if err := os.WriteFile(extra2, []byte("SHARED=same-run-value\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	host := []string{"DOCKER_HOST=tcp://demo-user:synthetic-password@internal-host/socket"}
	fp := mustFP(t)
	got, err := Collect(dir, []string{extra, extra2}, dir, host, fp)
	if err != nil {
		t.Fatal(err)
	}
	var docker, dsn, token, safe bool
	var fps []string
	for _, b := range got {
		switch b.Key {
		case "DOCKER_HOST":
			docker = b.Secret
		case "DATABASE_URL":
			dsn = b.Secret
		case "HOOK":
			token = b.Secret
		case "SAFE_URL":
			safe = !b.Secret
		case "SHARED":
			fps = append(fps, b.Fingerprint)
		}
	}
	if !docker || !dsn || !token || !safe {
		t.Fatalf("redaction docker=%v dsn=%v token=%v safe=%v", docker, dsn, token, safe)
	}
	if len(fps) != 2 || fps[0] != fps[1] {
		t.Fatalf("same-run fingerprints: %v", fps)
	}
	fp2 := mustFP(t)
	got2, err := Collect(dir, nil, dir, nil, fp2)
	if err != nil {
		t.Fatal(err)
	}
	var other string
	for _, b := range got2 {
		if b.Key == "SHARED" {
			other = b.Fingerprint
		}
	}
	if other == "" || other == fps[0] {
		t.Fatalf("cross-run fingerprints linked: %s vs %s", fps[0], other)
	}
}

func TestCollectNilFingerprinterFailsClosed(t *testing.T) {
	dir := t.TempDir()
	if _, err := Collect(dir, nil, dir, nil, nil); err == nil {
		t.Fatal("expected error")
	}
}

func TestMissingEnvFile(t *testing.T) {
	dir := t.TempDir()
	_, err := Collect(dir, []string{filepath.Join(dir, "nope.env")}, dir, nil, mustFP(t))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCollectSkipsUnselectedOversizedDotenv(t *testing.T) {
	dir := t.TempDir()
	big := append([]byte("IGNORED=from-dotenv\n"), bytes.Repeat([]byte("x"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, ".env"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("SELECTED=from-extra\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Collect(dir, []string{extra}, dir, nil, mustFP(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range got {
		if b.Key == "IGNORED" {
			t.Fatalf("unselected dotenv key collected: %+v", b)
		}
	}
	var hit bool
	for _, b := range got {
		if b.Key == "SELECTED" && b.RawValue == "from-extra" {
			hit = true
		}
	}
	if !hit {
		t.Fatal("selected env-file missing")
	}
}

func TestComposeEnvFileListIsCommaSeparated(t *testing.T) {
	a := filepath.Join(t.TempDir(), "a.env")
	b := filepath.Join(t.TempDir(), "b.env")
	got := ComposeEnvFileList([]string{"COMPOSE_ENV_FILES=" + a + "," + b})
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatalf("comma list: %v", got)
	}
	spaced := ComposeEnvFileList([]string{"COMPOSE_ENV_FILES=" + a + " , " + b})
	if len(spaced) != 2 || spaced[0] != a || spaced[1] != b {
		t.Fatalf("spaced comma list: %v", spaced)
	}
}

func TestReplacementEnvFilesExplicitOverridesPredefined(t *testing.T) {
	dir := t.TempDir()
	pre := filepath.Join(dir, "pre.env")
	explicit := filepath.Join(dir, "explicit.env")
	missing := filepath.Join(dir, "missing.env")
	got := ReplacementEnvFiles([]string{explicit}, []string{"COMPOSE_ENV_FILES=" + pre + "," + missing})
	if len(got) != 1 || got[0] != explicit {
		t.Fatalf("explicit must replace predefined: %v", got)
	}
	onlyPre := ReplacementEnvFiles(nil, []string{"COMPOSE_ENV_FILES=" + pre})
	if len(onlyPre) != 1 || onlyPre[0] != pre {
		t.Fatalf("predefined when no flags: %v", onlyPre)
	}
	none := ReplacementEnvFiles(nil, []string{"UNRELATED=1"})
	if len(none) != 0 {
		t.Fatalf("empty selected set: %v", none)
	}
}

func TestCollectSelectedOversizedDotenvFails(t *testing.T) {
	dir := t.TempDir()
	big := append([]byte("TOO_BIG=1\n"), bytes.Repeat([]byte("x"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, ".env"), big, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Collect(dir, nil, dir, nil, mustFP(t)); err == nil {
		t.Fatal("selected oversized .env must fail")
	}
}

func TestCollectMultipleFilesOrdered(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a.env")
	b := filepath.Join(dir, "b.env")
	if err := os.WriteFile(a, []byte("COLOR=from-a\nONLY_A=1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("COLOR=from-b\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := Collect(dir, []string{a, b}, dir, nil, mustFP(t))
	if err != nil {
		t.Fatal(err)
	}
	var color []string
	var onlyA bool
	for _, bind := range got {
		if bind.Key == "COLOR" {
			color = append(color, bind.RawValue)
		}
		if bind.Key == "ONLY_A" {
			onlyA = true
		}
	}
	if len(color) != 2 || color[0] != "from-a" || color[1] != "from-b" {
		t.Fatalf("order %v", color)
	}
	if !onlyA {
		t.Fatal("earlier file key dropped")
	}
}

func TestUnappliedExplicitProjectEnvNotListed(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("TAG=1.25\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	extra := filepath.Join(dir, "extra.env")
	if err := os.WriteFile(extra, []byte("HOSTV=repro-host\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if path, ok := UnappliedProjectEnv(dir, []string{".env"}, dir, nil); ok {
		t.Fatalf("explicit project .env listed unapplied: %s", path)
	}
	if path, ok := UnappliedProjectEnv(dir, []string{filepath.Join(dir, ".env")}, dir, nil); ok {
		t.Fatalf("absolute project .env listed unapplied: %s", path)
	}
	path, ok := UnappliedProjectEnv(dir, []string{extra}, dir, nil)
	if !ok || path == "" {
		t.Fatal("unselected project .env must still be unapplied")
	}
}
