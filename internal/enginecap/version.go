// SPDX-License-Identifier: Apache-2.0

package enginecap

import (
	"strconv"
	"strings"
	"unicode"
)

func major(version string) (int, bool) {
	s := strings.TrimSpace(version)
	s = strings.TrimPrefix(s, "v")
	s = strings.TrimPrefix(s, "V")
	if s == "" {
		return 0, false
	}
	var b strings.Builder
	for _, r := range s {
		if unicode.IsDigit(r) {
			b.WriteRune(r)
			continue
		}
		break
	}
	if b.Len() == 0 {
		return 0, false
	}
	n, err := strconv.Atoi(b.String())
	if err != nil {
		return 0, false
	}
	return n, true
}
