// SPDX-License-Identifier: Apache-2.0

//go:build unix

package safety

import (
	"path/filepath"
	"strings"
	"syscall"
)

const openNonblock = syscall.O_NONBLOCK

// pseudoFile reports whether path, after resolving symlinks, lies in a
// kernel pseudo-file system. Entries there stat as regular files of size 0
// but expose process or device state (for example /proc/self/environ).
func pseudoFile(path string) bool {
	p, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if r, err := filepath.EvalSymlinks(p); err == nil {
		p = r
	}
	for _, root := range []string{"/proc", "/sys", "/dev"} {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}
