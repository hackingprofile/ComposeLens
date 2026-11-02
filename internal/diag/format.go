// SPDX-License-Identifier: Apache-2.0

package diag

import (
	"fmt"

	"composelens/internal/redact"
)

// FormatHuman appends code, remediation, and doc link after the existing message line.
func FormatHuman(message string, ent Entry) string {
	message = redact.EscapeControls(message)
	if ent.ID == "" {
		return fmt.Sprintf("composelens: %s\n", message)
	}
	return fmt.Sprintf("composelens: %s\ncode: %s\nremediation: %s\nSee %s\n", message, ent.ID, ent.Remediation, ent.Doc)
}
