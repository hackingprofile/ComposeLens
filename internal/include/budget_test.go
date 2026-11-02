// SPDX-License-Identifier: Apache-2.0

package include

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/safety"
)

func TestTransitiveIncludeExceedsSharedBudget(t *testing.T) {
	dir := t.TempDir()
	pad := bytes.Repeat([]byte("#"), 900*1024)
	names := []string{"compose.yaml", "a.yaml", "b.yaml", "c.yaml", "d.yaml"}
	for i, name := range names {
		var body string
		if i+1 < len(names) {
			body = fmt.Sprintf("include:\n  - %s\nservices:\n  s%d:\n    image: alpine\n", names[i+1], i)
		} else {
			body = fmt.Sprintf("services:\n  s%d:\n    image: alpine\n", i)
		}
		if err := os.WriteFile(filepath.Join(dir, name), append([]byte(body), pad...), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root := filepath.Join(dir, "compose.yaml")
	bgt := safety.NewBudget()
	files, err := discover.Discover(dir, dir, []string{root}, "", bgt)
	if err != nil {
		t.Fatal(err)
	}
	doc, err := composeparse.Parse(files[0])
	if err != nil {
		t.Fatal(err)
	}
	got := Expand(doc, LoaderWithBudget(bgt), nil)
	if !safety.IsResourceBound(got.Err) || safety.CodeOf(got.Err) != safety.CodeTotalTooLarge {
		t.Fatalf("want aggregate fail, got %v", got.Err)
	}

	raw, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	unbounded, err := composeparse.Parse(discover.File{Path: root, Bytes: raw, Origin: "include"})
	if err != nil {
		t.Fatal(err)
	}
	ok := Expand(unbounded, DiskLoad, nil)
	if ok.Err != nil {
		t.Fatalf("nil-budget DiskLoad still loads per-file-legal trees: %v", ok.Err)
	}
	if len(ok.Docs) < 2 {
		t.Fatalf("expected transitive docs, got %d", len(ok.Docs))
	}
}
