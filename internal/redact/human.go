// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"

	"composelens/internal/idpath"
)

// IsComposeIdentity reports whether s is a provenance identity label
// (services.<name>… or <name>:VAR), not a secret value.
func IsComposeIdentity(s string) bool {
	if s == "" {
		return false
	}
	if strings.HasPrefix(s, idpath.Root) {
		return true
	}
	if strings.Contains(s, "://") || strings.ContainsAny(s, `/\`) {
		return false
	}
	i := strings.LastIndexByte(s, ':')
	if i <= 0 || i == len(s)-1 {
		return false
	}
	return idpath.EnvOK(s[i+1:])
}

// DisplayHuman shows identity labels and non-secret strings. Secret-shaped
// VALUES become [redacted]. Genuine filesystem paths are not secret-shaped
// (see LooksLikeSecret / genuineFilesystemPath) and stay visible, matching
// inspect and TestHumanShowsFilesystemPathProvenanceJSONUnchanged.
func DisplayHuman(s string) string {
	if s == "" {
		return s
	}
	if IsComposeIdentity(s) {
		return EscapeControls(s)
	}
	if LooksLikeSecret(s) {
		return TokenRedacted
	}
	return EscapeControls(s)
}
