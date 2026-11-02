// SPDX-License-Identifier: Apache-2.0

package paths

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func Canonical(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("empty path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func Resolve(base, rel string) (string, error) {
	if rel == "" {
		return "", fmt.Errorf("empty path")
	}
	if filepath.IsAbs(rel) {
		return Canonical(rel)
	}
	if base == "" {
		return Canonical(rel)
	}
	return Canonical(filepath.Join(base, rel))
}

func ProjectDir(cwd, flag string, firstFile string) (string, error) {
	if flag != "" {
		return Canonical(flag)
	}
	if firstFile != "" {
		abs, err := Canonical(firstFile)
		if err != nil {
			return "", err
		}
		return filepath.Dir(abs), nil
	}
	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return "", err
		}
	}
	return Canonical(cwd)
}

func JoinClean(base, rel string) string {
	if filepath.IsAbs(rel) {
		return filepath.Clean(rel)
	}
	return filepath.Clean(filepath.Join(base, rel))
}

// Within reports whether target lies inside root after both are made
// absolute and every symlink is resolved. A path that cannot be resolved is
// compared as written. On Windows the comparison ignores case.
func Within(root, target string) bool {
	r, err := resolved(root)
	if err != nil {
		return false
	}
	t, err := resolved(target)
	if err != nil {
		return false
	}
	rel, err := filepath.Rel(r, t)
	if err != nil {
		return false
	}
	if rel == "." {
		return true
	}
	if filepath.IsAbs(rel) || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func resolved(p string) (string, error) {
	abs, err := Canonical(p)
	if err != nil {
		return "", err
	}
	if r, err := filepath.EvalSymlinks(abs); err == nil {
		abs = r
	}
	if runtime.GOOS == "windows" {
		abs = strings.ToLower(abs)
	}
	return filepath.Clean(abs), nil
}
