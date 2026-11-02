// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"composelens/internal/normalize"
	"composelens/internal/shortvol"
)

const (
	ClassByDesign          = "by-design"
	ClassKnownLimitation   = "known-limitation"
	DetailD1BindAsWritten  = "explained/by-design (D1): ComposeLens keeps bind volume source as written (portable, deterministic); the engine resolves a host-absolute path. See docs/normalize.md and docs/differential.md"
	DetailD2ShellVsExec    = "explained/by-design (D2): ComposeLens preserves shell-string vs exec-argv as written (Compose spec: they are not semantically identical); docker compose config dumps shell form as exec argv. See docs/normalize.md and docs/differential.md"
	DetailD3DefaultNetwork = "explained/by-design (D3): ComposeLens models source-declared configuration and does not synthesize the engine's implicit default network; the engine injects `default`. See docs/differential.md"
	DetailD4NestedDefault  = "explained/known-limitation (D4): default text nested more than 8 levels deep is kept as written; the engine expands it. See docs/interpolation.md"
)

var leftoverDollar = regexp.MustCompile(`^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$`)

func annotateFamilyDivergence(row *Row, ls, rs normalize.Service, root string) {
	if row == nil || row.State != StateDivergent || row.Detail != "" {
		return
	}
	switch {
	case strings.HasSuffix(root, ".volumes"):
		if d1BindSourceAsWritten(ls.Volumes, rs.Volumes) {
			row.Classification = ClassByDesign
			row.Detail = DetailD1BindAsWritten
		}
	case strings.HasSuffix(root, ".command"):
		if d2ShellVsExecDump(ls.Command, rs.Command) {
			row.Classification = ClassByDesign
			row.Detail = DetailD2ShellVsExec
		}
	case strings.HasSuffix(root, ".entrypoint"):
		if d2ShellVsExecDump(ls.Entrypoint, rs.Entrypoint) {
			row.Classification = ClassByDesign
			row.Detail = DetailD2ShellVsExec
		}
	}
}

func annotateEnvDivergence(row *Row, internal, engine string) {
	if row == nil || row.State != StateDivergent || row.Secret || row.Detail != "" {
		return
	}
	if d4UnexpandedDefault(internal, engine) {
		row.Classification = ClassKnownLimitation
		row.Detail = DetailD4NestedDefault
	}
}

func annotateDefaultNetworks(row *Row) {
	if row == nil || row.Classification != "" {
		return
	}
	if row.State != StateOnlyEngine && row.State != StateDivergent {
		return
	}
	if !strings.HasSuffix(row.Path, ".networks") {
		return
	}
	if !d3ImplicitDefaultNetwork(row.Internal, row.Engine, row.State) {
		return
	}
	row.Classification = ClassByDesign
	row.Detail = DetailD3DefaultNetwork
}

func d1BindSourceAsWritten(internal, engine []normalize.Volume) bool {
	if len(internal) == 0 || len(internal) != len(engine) {
		return false
	}
	used := make([]bool, len(engine))
	d1 := 0
	for _, iv := range internal {
		j := -1
		for k, ev := range engine {
			if used[k] {
				continue
			}
			if iv.Target == ev.Target {
				j = k
				break
			}
		}
		if j < 0 {
			return false
		}
		used[j] = true
		ev := engine[j]
		if !volumeEqualExceptSource(iv, ev) {
			return false
		}
		if iv.Source == ev.Source {
			continue
		}
		if isBind(iv) && isBind(ev) && relativeHostPath(iv.Source) && absoluteHostPath(ev.Source) {
			d1++
			continue
		}
		return false
	}
	return d1 > 0
}

func volumeEqualExceptSource(a, b normalize.Volume) bool {
	return a.Type == b.Type &&
		a.Target == b.Target &&
		a.ReadOnly == b.ReadOnly &&
		a.SELinux == b.SELinux &&
		a.Propagation == b.Propagation &&
		a.Nocopy == b.Nocopy &&
		a.Subpath == b.Subpath &&
		a.TmpfsSize == b.TmpfsSize &&
		a.TmpfsMode == b.TmpfsMode &&
		a.CreateHost == b.CreateHost &&
		strings.Join(a.Extra, ",") == strings.Join(b.Extra, ",")
}

func isBind(v normalize.Volume) bool {
	return strings.EqualFold(v.Type, "bind")
}

func relativeHostPath(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" || absoluteHostPath(s) {
		return false
	}
	return strings.HasPrefix(s, ".") || !filepath.IsAbs(s)
}

func absoluteHostPath(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	if filepath.IsAbs(s) || strings.HasPrefix(s, "/") || shortvol.WindowsDrive(s) {
		return true
	}
	return false
}

func d2ShellVsExecDump(internal, engine *normalize.Command) bool {
	if internal == nil || engine == nil {
		return false
	}
	if internal.Form != normalize.FormShell || engine.Form != normalize.FormExec {
		return false
	}
	shell := strings.TrimSpace(internal.Shell)
	if shell == "" {
		return false
	}
	joined := strings.Join(engine.Argv, " ")
	if joined == shell {
		return true
	}
	// The engine splits a shell string into words the way a POSIX shell does
	// (quotes group, backslash escapes), not on every space.
	fields := shellWords(shell)
	if len(fields) == len(engine.Argv) {
		ok := true
		for i := range fields {
			if fields[i] != engine.Argv[i] {
				ok = false
				break
			}
		}
		if ok {
			return true
		}
	}
	n := len(engine.Argv)
	if n >= 3 {
		head := strings.ToLower(engine.Argv[0])
		if (head == "sh" || head == "/bin/sh" || head == "bash" || head == "/bin/bash" || head == "cmd" || head == "cmd.exe") && engine.Argv[n-1] == shell {
			return true
		}
	}
	return false
}

func d4UnexpandedDefault(internal, engine string) bool {
	internal = strings.TrimSpace(internal)
	engine = strings.TrimSpace(engine)
	if internal == "" || engine == "" || internal == engine {
		return false
	}
	if !leftoverDollar.MatchString(internal) {
		return false
	}
	if leftoverDollar.MatchString(engine) {
		return false
	}
	return true
}

func d3ImplicitDefaultNetwork(internal, engine, state string) bool {
	eKeys := networkKeys(engine)
	if len(eKeys) == 0 {
		return false
	}
	if state == StateOnlyEngine {
		return solelyDefault(eKeys)
	}
	if state == StateDivergent {
		return extraDefaultOnly(networkKeys(internal), eKeys)
	}
	return false
}

func networkKeys(bundle string) []string {
	s := strings.TrimSpace(bundle)
	s = strings.TrimPrefix(s, "{")
	s = strings.TrimSuffix(s, "}")
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var keys []string
	for _, p := range strings.Split(s, "; ") {
		if p == "" {
			continue
		}
		k, _, _ := strings.Cut(p, "=")
		k = strings.TrimSpace(k)
		if k != "" {
			keys = append(keys, k)
		}
	}
	sort.Strings(keys)
	return keys
}

func solelyDefault(keys []string) bool {
	return len(keys) == 1 && keys[0] == "default"
}

func extraDefaultOnly(internal, engine []string) bool {
	hasDefault := false
	rest := make([]string, 0, len(engine))
	for _, k := range engine {
		if k == "default" {
			hasDefault = true
			continue
		}
		rest = append(rest, k)
	}
	if !hasDefault {
		return false
	}
	for _, k := range internal {
		if k == "default" {
			return false
		}
	}
	if len(rest) != len(internal) {
		return false
	}
	for i := range rest {
		if rest[i] != internal[i] {
			return false
		}
	}
	return true
}

// shellWords splits s into words with POSIX shell quoting: single quotes
// keep everything literal, double quotes group and allow escaped quotes and
// backslashes, and a backslash outside quotes escapes the next character.
func shellWords(s string) []string {
	var out []string
	var cur strings.Builder
	inWord := false
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				cur.WriteByte(c)
			}
		case quote == '"':
			switch {
			case c == '"':
				quote = 0
			case c == '\\' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\' || s[i+1] == '$' || s[i+1] == '`'):
				i++
				cur.WriteByte(s[i])
			default:
				cur.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
			inWord = true
		case c == '\\' && i+1 < len(s):
			i++
			cur.WriteByte(s[i])
			inWord = true
		case c == ' ' || c == '\t' || c == '\n':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}
