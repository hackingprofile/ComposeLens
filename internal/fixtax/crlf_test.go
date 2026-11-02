// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestByteExactFixturesKeepCRLF: the fixtures .gitattributes marks -text are
// checked out byte for byte, and every line of each ends in CRLF. A checkout
// or an editor that converts them to LF would silently stop testing CRLF.
func TestByteExactFixturesKeepCRLF(t *testing.T) {
	root := filepath.Join("..", "..")
	attrs, err := os.ReadFile(filepath.Join(root, ".gitattributes"))
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	sc := bufio.NewScanner(bytes.NewReader(attrs))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 || f[1] != "-text" || strings.HasPrefix(f[0], "#") {
			continue
		}
		pattern := f[0]
		if dir, ok := strings.CutSuffix(pattern, "/**"); ok {
			entries, err := os.ReadDir(filepath.Join(root, filepath.FromSlash(dir)))
			if err != nil {
				t.Fatalf("%s: %v", pattern, err)
			}
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, dir+"/"+e.Name())
				}
			}
			continue
		}
		files = append(files, pattern)
	}
	if len(files) < 6 {
		t.Fatalf("found %d -text fixtures in .gitattributes, want at least 6: %v", len(files), files)
	}
	for _, rel := range files {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		lf := bytes.Count(raw, []byte("\n"))
		crlf := bytes.Count(raw, []byte("\r\n"))
		if lf == 0 || crlf != lf {
			t.Errorf("%s: %d of %d line endings are CRLF, want all", rel, crlf, lf)
		}
	}
}
