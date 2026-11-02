// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"composelens/internal/safety"
)

func write(t *testing.T, dir, name, body string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestExplicitFileOrder(t *testing.T) {
	dir := t.TempDir()
	a := write(t, dir, "a.yaml", "services: {a: {image: alpine}}\n")
	b := write(t, dir, "b.yaml", "services: {b: {image: alpine}}\n")
	files, err := Discover(dir, dir, []string{b, a}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("len=%d", len(files))
	}
	if filepath.Base(files[0].Path) != "b.yaml" || filepath.Base(files[1].Path) != "a.yaml" {
		t.Fatalf("order: %s then %s", files[0].Path, files[1].Path)
	}
	if files[0].Origin != "flag" || files[0].Digest == files[1].Digest {
		t.Fatalf("origin/digest: %+v", files)
	}
}

func TestComposeFileEnvOrder(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "one.yaml", "services: {}\n")
	write(t, dir, "two.yaml", "services: {}\n")
	sep := string(os.PathListSeparator)
	env := filepath.Join(dir, "one.yaml") + sep + filepath.Join(dir, "two.yaml")
	files, err := Discover(dir, dir, nil, env)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 || filepath.Base(files[0].Path) != "one.yaml" || files[0].Origin != "compose-file-env" {
		t.Fatalf("%+v", files)
	}
}

func TestDefaultAndOverride(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "compose.yaml", "services: {web: {image: nginx}}\n")
	write(t, dir, "compose.override.yaml", "services: {web: {ports: ['80:80']}}\n")
	files, err := Discover(dir, dir, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 2 {
		t.Fatalf("len=%d", len(files))
	}
	if filepath.Base(files[0].Path) != "compose.yaml" || filepath.Base(files[1].Path) != "compose.override.yaml" {
		t.Fatalf("defaults: %+v", files)
	}
}

func TestExplicitDisablesOverrideAutoload(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "compose.yaml", "services: {}\n")
	write(t, dir, "compose.override.yaml", "services: {}\n")
	files, err := Discover(dir, dir, []string{filepath.Join(dir, "compose.yaml")}, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 {
		t.Fatalf("len=%d", len(files))
	}
}

func TestMissingExplicitFile(t *testing.T) {
	dir := t.TempDir()
	_, err := Discover(dir, dir, []string{filepath.Join(dir, "nope.yaml")}, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPreferComposeYamlOverDockerCompose(t *testing.T) {
	dir := t.TempDir()
	write(t, dir, "docker-compose.yml", "services: {old: {image: alpine}}\n")
	write(t, dir, "compose.yaml", "services: {new: {image: alpine}}\n")
	files, err := Discover(dir, dir, nil, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || filepath.Base(files[0].Path) != "compose.yaml" {
		t.Fatalf("%+v", files)
	}
}

func TestPathListSeparatorMatchesGOOS(t *testing.T) {
	want := ";"
	if runtime.GOOS != "windows" {
		want = ":"
	}
	if string(os.PathListSeparator) != want {
		t.Fatalf("separator %q on %s", string(os.PathListSeparator), runtime.GOOS)
	}
}

func TestRefuseOversizeFile(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "compose.yaml")
	raw := append([]byte("services:\n  web:\n    image: alpine\n"), bytes.Repeat([]byte("#"), safety.MaxFileBytes)...)
	if err := os.WriteFile(p, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Discover(dir, dir, []string{p}, "")
	if safety.CodeOf(err) != safety.CodeFileTooLarge {
		t.Fatalf("got %s %v", safety.CodeOf(err), err)
	}
}

func TestRefuseTotalOversize(t *testing.T) {
	dir := t.TempDir()
	chunk := bytes.Repeat([]byte("#"), 900*1024)
	body := append([]byte("services:\n  web:\n    image: alpine\n"), chunk...)
	var paths []string
	for i := 0; i < 5; i++ {
		p := filepath.Join(dir, string(rune('a'+i))+".yaml")
		if err := os.WriteFile(p, body, 0o644); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, p)
	}
	_, err := Discover(dir, dir, paths, "")
	if safety.CodeOf(err) != safety.CodeTotalTooLarge {
		t.Fatalf("got %s %v", safety.CodeOf(err), err)
	}
}
