// SPDX-License-Identifier: Apache-2.0

package ci

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestChangelogHasOneEntryPerVersion(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "CHANGELOG.md"))
	if err != nil {
		t.Fatal(err)
	}
	entries := regexp.MustCompile(`(?m)^## \[([^\]]+)\].*$`).FindAllStringSubmatch(string(raw), -1)
	if len(entries) != 1 || entries[0][1] != "0.1.0" {
		t.Fatalf("want one 0.1.0 entry, got %v", entries)
	}
	if strings.Contains(string(raw), "last-word key rule") {
		t.Fatal("changelog describes an obsolete key classifier")
	}
}
