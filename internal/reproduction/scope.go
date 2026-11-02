// SPDX-License-Identifier: Apache-2.0

package reproduction

import (
	"strings"

	"composelens/internal/differential"
)

// ModeledRow is the canonical-compare scope used by the live corpus
// MATCH assertion (image/hostname/working_dir/user/ports/command/entrypoint/dns/volumes
// and container-env). Default engine-injected networks are out of scope.
func ModeledRow(row differential.Row) bool {
	switch row.Kind {
	case differential.KindEnv:
		return true
	case differential.KindField:
		rest := row.Path
		if i := strings.LastIndex(rest, "."); i >= 0 {
			rest = rest[i+1:]
		}
		switch rest {
		case "image", "hostname", "working_dir", "user", "ports", "command", "entrypoint", "dns", "volumes":
			return true
		default:
			return false
		}
	default:
		return false
	}
}
