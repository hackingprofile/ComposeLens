// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"fmt"
	"strings"

	"composelens/internal/redact"
)

func Human(r Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ComposeLens differential (internal vs engine)\n")
	fmt.Fprintf(&b, "Engine: %s", redact.EscapeControls(dash(r.EngineState)))
	if r.Version != "" {
		fmt.Fprintf(&b, "  %s", redact.EscapeControls(r.Version))
	}
	if r.SkipReason != "" {
		fmt.Fprintf(&b, " (%s)", redact.EscapeControls(r.SkipReason))
	}
	b.WriteByte('\n')
	if r.Command != "" {
		fmt.Fprintf(&b, "Command: %s\n", redact.EscapeControls(r.Command))
	}
	fmt.Fprintf(&b, "Summary: match=%d divergent=%d only-internal=%d only-engine=%d uncertain=%d\n",
		r.Summary.Match, r.Summary.Divergent, r.Summary.OnlyInternal, r.Summary.OnlyEngine, r.Summary.Uncertain)
	fmt.Fprintf(&b, "%s\n", redact.EscapeControls(r.Disclaimer))
	for _, row := range r.Rows {
		fmt.Fprintf(&b, "  %s  %s  %s", redact.EscapeControls(row.State), redact.EscapeControls(row.Kind), redact.EscapeControls(row.Path))
		if row.State == StateDivergent || row.State == StateUncertain {
			fmt.Fprintf(&b, "  internal=%s  engine=%s", redact.EscapeControls(dash(row.Internal)), redact.EscapeControls(dash(row.Engine)))
		}
		if row.Detail != "" {
			fmt.Fprintf(&b, "  (%s)", redact.EscapeControls(row.Detail))
		}
		if row.Secret {
			fmt.Fprintf(&b, "  secret")
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func SecretFragments(r Report) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if s == "" || s == "[redacted]" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	for _, row := range r.Rows {
		if !row.Secret {
			continue
		}
		add(row.Internal)
		add(row.Engine)
	}
	return out
}
