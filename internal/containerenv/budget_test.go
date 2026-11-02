// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/safety"
)

func TestOversizedEnvFileTyped(t *testing.T) {
	dir := t.TempDir()
	huge := append([]byte("COLOR=blue\n"), bytes.Repeat([]byte("#"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, "huge.env"), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    env_file: huge.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(fieldsOf(t, dir), nil, nil, safety.NewBudget())
	if !safety.IsResourceBound(err) || safety.CodeOf(err) != safety.CodeFileTooLarge {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), "COLOR=blue") || strings.Contains(err.Error(), string(huge[:32])) {
		t.Fatalf("leaked content: %s", err)
	}
}

func TestEnvFileChargesSharedBudget(t *testing.T) {
	dir := t.TempDir()
	pad := bytes.Repeat([]byte("#"), 900*1024)
	var list strings.Builder
	list.WriteString("services:\n  web:\n    image: alpine\n    env_file:\n")
	for i := 0; i < 5; i++ {
		name := fmt.Sprintf("e%d.env", i)
		if err := os.WriteFile(filepath.Join(dir, name), append([]byte("K=v\n"), pad...), 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&list, "      - %s\n", name)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(list.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(fieldsOf(t, dir), nil, nil, safety.NewBudget())
	if !safety.IsResourceBound(err) || safety.CodeOf(err) != safety.CodeTotalTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestEnvFileFileCountCap(t *testing.T) {
	dir := t.TempDir()
	tiny := []byte("K=v\n")
	var list strings.Builder
	list.WriteString("services:\n  web:\n    image: alpine\n    env_file:\n")
	for i := 0; i < safety.MaxTotalFiles+1; i++ {
		name := fmt.Sprintf("e%03d.env", i)
		if err := os.WriteFile(filepath.Join(dir, name), tiny, 0o644); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&list, "      - %s\n", name)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(list.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(fieldsOf(t, dir), nil, nil, safety.NewBudget())
	if !safety.IsResourceBound(err) || safety.CodeOf(err) != safety.CodeTooManyFiles {
		t.Fatalf("got %v", err)
	}
}

func TestSecretShapedEnvFilePath(t *testing.T) {
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	dir := t.TempDir()
	secretDir := filepath.Join(dir, probe)
	if err := os.Mkdir(secretDir, 0o755); err != nil {
		t.Fatal(err)
	}
	huge := append([]byte("COLOR=blue\n"), bytes.Repeat([]byte("#"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(secretDir, "huge.env"), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(secretDir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    env_file: huge.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(fieldsOf(t, secretDir), nil, nil, safety.NewBudget())
	if !safety.IsResourceBound(err) {
		t.Fatalf("got %v", err)
	}
	if strings.Contains(err.Error(), probe) {
		t.Fatalf("leaked secret path: %s", err)
	}
	if !strings.Contains(err.Error(), "<redacted>") {
		t.Fatalf("want <redacted>: %s", err)
	}
}

func TestNilBudgetStillPerFileBound(t *testing.T) {
	dir := t.TempDir()
	huge := append([]byte("COLOR=blue\n"), bytes.Repeat([]byte("#"), safety.MaxFileBytes)...)
	if err := os.WriteFile(filepath.Join(dir, "huge.env"), huge, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte("services:\n  web:\n    image: alpine\n    env_file: huge.env\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(fieldsOf(t, dir), nil, nil)
	if !safety.IsResourceBound(err) || safety.CodeOf(err) != safety.CodeFileTooLarge {
		t.Fatalf("nil budget must still bound per-file: %v", err)
	}
}
