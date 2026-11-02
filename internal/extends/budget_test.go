// SPDX-License-Identifier: Apache-2.0

package extends

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

func TestCrossFileExtendsExceedsSharedBudget(t *testing.T) {
	dir := t.TempDir()
	pad := bytes.Repeat([]byte("#"), 900*1024)
	names := []string{"compose.yaml", "a.yaml", "b.yaml", "c.yaml", "d.yaml"}
	for i, name := range names {
		var body string
		if i+1 < len(names) {
			body = fmt.Sprintf("services:\n  web:\n    extends:\n      file: %s\n      service: web\n    image: alpine\n", names[i+1])
		} else {
			body = "services:\n  web:\n    image: alpine\n"
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
	got := Apply(doc, LoaderWithBudget(bgt), nil)
	if !safety.IsResourceBound(got.Err) || safety.CodeOf(got.Err) != safety.CodeTotalTooLarge {
		t.Fatalf("want aggregate fail, got %v", got.Err)
	}

	raw, err := os.ReadFile(root)
	if err != nil {
		t.Fatal(err)
	}
	unbounded, err := composeparse.Parse(discover.File{Path: root, Bytes: raw, Origin: "extends"})
	if err != nil {
		t.Fatal(err)
	}
	ok := Apply(unbounded, DiskLoad, nil)
	if ok.Err != nil {
		t.Fatalf("nil-budget DiskLoad still loads per-file-legal trees: %v", ok.Err)
	}
}
