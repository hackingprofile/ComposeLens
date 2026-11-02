// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"composelens/internal/diag"
	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/explain"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

// Short secrets. A collected secret value shorter than
// safety.MinScanLen bytes cannot be scanned for reliably, so a command whose
// output can carry project values refuses (exit 4) unless the key is named
// with --allow-short-secret. doctor and reproduce carry no project values and
// do not refuse for a short secret; they still guard long secrets and
// recognized tokens.

// shortSource is where a short secret value was collected: key, file, line.
type shortSource struct {
	Key   string
	File  string
	Line  int
	value string
}

func isShort(v string) bool { return v != "" && len(v) < safety.MinScanLen }

// shortSources lists every short secret value the command collected, with
// its key and location: env sources (.env, --env-file), Compose fields after
// merge (disabled services included) and container-environment sources.
func shortSources(binds []envsrc.Binding, in *explain.Input) []shortSource {
	var out []shortSource
	seen := map[string]struct{}{}
	add := func(key, file string, line int, v string) {
		if !isShort(v) {
			return
		}
		k := key + "\x00" + file + "\x00" + fmt.Sprint(line) + "\x00" + v
		if _, ok := seen[k]; ok {
			return
		}
		seen[k] = struct{}{}
		out = append(out, shortSource{Key: key, File: file, Line: line, value: v})
	}
	for _, b := range binds {
		if b.Secret {
			add(b.Key, b.Path, b.Line, b.RawValue)
		}
	}
	if in != nil {
		for _, f := range in.Merge {
			key := f.Path[strings.LastIndex(f.Path, ".")+1:]
			if f.Secret || redact.MustRedact(key, f.Value) {
				add(key, f.Winner, f.Line, f.Value)
			}
		}
		for _, se := range in.Container {
			for _, v := range se.Vars {
				if !v.Secret {
					continue
				}
				add(v.Key, v.Winner.Path, v.Winner.Line, v.Value)
				for _, o := range v.Overridden {
					add(v.Key, o.Path, o.Line, o.Value)
				}
			}
		}
	}
	return out
}

// screenSecrets drops short values the command may emit without a byte scan
// and reports the short values that must refuse the output.
func (rt Runtime) screenSecrets(secrets []string) (kept []string, refused []shortSource) {
	_, carriesValues := shortSecretCommands[rt.opt.Command]
	allow := map[string]bool{}
	for _, k := range rt.opt.AllowShortSecret {
		allow[k] = true
	}
	seenShort := map[string]bool{}
	for _, s := range secrets {
		if !isShort(s) {
			kept = append(kept, s)
			continue
		}
		if !carriesValues || seenShort[s] {
			continue
		}
		seenShort[s] = true
		var blocking []shortSource
		named := false
		for _, src := range rt.short {
			if src.value != s {
				continue
			}
			named = true
			if !allow[src.Key] && !redact.OrdinaryShortOption(src.Key, src.value) {
				blocking = append(blocking, src)
			}
		}
		if !named {
			blocking = append(blocking, shortSource{Key: "", value: s})
		}
		refused = append(refused, blocking...)
	}
	return kept, refused
}

// guardOutput applies the short-secret policy, then the output guard.
func (rt Runtime) guardOutput(raw []byte, secrets []string) (int, bool) {
	kept, refused := rt.screenSecrets(secrets)
	if len(refused) > 0 {
		return rt.refuseShort(refused, kept), false
	}
	if err := safety.GuardWithRevisions(raw, kept, rt.publicRevisions); err != nil {
		writeErr(rt.Stderr, "composelens: refuse to write output: fail-closed (%s)\n", err.Error())
		return exitcode.Safety, false
	}
	return exitcode.OK, true
}

func (rt *Runtime) rememberPublicRevisions(in explain.Input) {
	for _, f := range in.Merge {
		if !f.Secret && redact.PublicRevision(f.Path, f.Value) {
			rt.publicRevisions = append(rt.publicRevisions, f.Value)
		}
	}
	for _, service := range in.Container {
		for _, v := range service.Vars {
			if !v.Secret && redact.PublicRevision(v.Key, v.Value) {
				rt.publicRevisions = append(rt.publicRevisions, v.Value)
			}
		}
	}
}

// refuseShort writes the short-secret refusal in the selected format: stable
// code, the key and file:line of each short value (never the value), a
// remediation and a doc link. Exit 4.
func (rt Runtime) refuseShort(refused []shortSource, longSecrets []string) int {
	values := map[string]bool{}
	for _, r := range refused {
		values[strings.ToLower(r.value)] = true
	}
	mentions := func(s string) bool {
		low := strings.ToLower(s)
		for v := range values {
			if strings.Contains(low, v) {
				return true
			}
		}
		return false
	}
	var parts []string
	seen := map[string]bool{}
	for _, r := range refused {
		key := r.Key
		if key == "" || mentions(key) {
			key = "a secret-keyed value"
		}
		where := ""
		if r.File != "" && !mentions(r.File) {
			where = r.File
			if r.Line > 0 {
				where += fmt.Sprintf(":%d", r.Line)
			}
		}
		p := key
		if where != "" {
			p += " (" + where + ")"
		}
		if !seen[p] {
			seen[p] = true
			parts = append(parts, p)
		}
	}
	sort.Strings(parts)
	msg := fmt.Sprintf("refuse to write output: a collected secret value is shorter than %d bytes and cannot be scanned for reliably: %s", safety.MinScanLen, strings.Join(parts, ", "))
	ent, _ := diag.LookupID("safety.short-secret")
	raw := rt.errorBytes(msg, ent)
	if safety.Guard(append([]byte(nil), raw...), longSecrets) != nil {
		raw = rt.errorBytes(fmt.Sprintf("refuse to write output: a collected secret value is shorter than %d bytes", safety.MinScanLen), ent)
	}
	writeErr(rt.Stderr, "%s", string(raw))
	return exitcode.Safety
}

// errorBytes renders a diagnostic in the selected format (composelens.error.v0
// for --json, the catalog fields for human output).
func (rt Runtime) errorBytes(msg string, ent diag.Entry) []byte {
	if rt.opt.JSON {
		encoded, err := json.MarshalIndent(errorReport{
			Schema: "composelens.error.v0", State: evidence.Known, Message: msg,
			Code: ent.ID, Remediation: ent.Remediation, Doc: ent.Doc,
		}, "", "  ")
		if err == nil {
			return append(encoded, '\n')
		}
	}
	return []byte(diag.FormatHuman(msg, ent))
}

// recordAllowShortSecret adds the opt-in to a JSON object document.
func (rt Runtime) recordAllowShortSecret(raw []byte) []byte {
	if len(rt.opt.AllowShortSecret) == 0 {
		return raw
	}
	trimmed := bytes.TrimRight(raw, "\n")
	if len(trimmed) < 2 || trimmed[0] != '{' || trimmed[len(trimmed)-1] != '}' {
		return raw
	}
	var top map[string]json.RawMessage
	if json.Unmarshal(trimmed, &top) != nil {
		return raw
	}
	if _, done := top["allowShortSecret"]; done {
		return raw
	}
	keys, err := json.Marshal(rt.opt.AllowShortSecret)
	if err != nil {
		return raw
	}
	body := bytes.TrimRight(trimmed[:len(trimmed)-1], " \n")
	var b bytes.Buffer
	b.Write(body)
	if len(bytes.TrimSpace(body)) > 1 {
		b.WriteString(",")
	}
	b.WriteString("\n  \"allowShortSecret\": ")
	b.Write(keys)
	b.WriteString("\n}\n")
	return b.Bytes()
}

// warnAllowShortSecret prints the opt-in acknowledgement (never a value).
func (rt Runtime) warnAllowShortSecret() {
	if len(rt.opt.AllowShortSecret) == 0 {
		return
	}
	writeErr(rt.Stderr, "composelens: warning: --allow-short-secret %s: values under these keys may be shorter than %d bytes and are not byte-scanned; they stay withheld in every view\n",
		strings.Join(rt.opt.AllowShortSecret, ", "), safety.MinScanLen)
}
