// SPDX-License-Identifier: Apache-2.0

package diag

// Entry is one catalogued diagnostic. Templates never embed secrets.
type Entry struct {
	ID          string
	Message     string
	Remediation string
	Doc         string
}

func e(id, msg, rem, doc string) Entry {
	return Entry{ID: id, Message: msg, Remediation: rem, Doc: doc}
}

var catalog = []Entry{
	e("exit.internal", "An unexpected internal failure occurred.", "Retry with the same arguments. If it repeats, capture stderr without secrets and file an issue with the command (not the project contents).", "docs/cli.md#exit-codes"),
	e("cli.usage", "The command line is not valid for this command.", "Fix the flag, operand, or command name. Empty values and flags used as values are usage errors. See the per-command flag matrix.", "docs/cli.md"),
	e("exit.input", "Inputs could not be read or parsed.", "Check that named files exist, Compose YAML is well-formed, and policy/redaction files validate. Hostile or oversized input fails typed before analysis.", "docs/parser.md"),
	e("exit.safety", "Output was refused because a secret might leak or safety was uncertain.", "Do not disable the guard. Remove secret-shaped values from paths and diagnostics, then retry. Fingerprint-key generation failures are also fail-closed.", "docs/privacy.md"),
	e("safety.short-secret", "A collected secret value is shorter than 6 bytes, so the output cannot be scanned for it reliably.", "Use a secret value of at least 6 bytes, or name each key with --allow-short-secret <KEY> to accept its short value: it stays withheld in every view but is not byte-scanned. Moving the value into .env does not help (it is still collected); disabled services count.", "docs/privacy.md"),
	e("exit.unsupported", "The requested command or mode is not implemented in this version.", "Use a 0.1.0 command (doctor, inspect, explain, diff, check, differential, reproduce, version, report --json, report --html). The human report is reserved.", "docs/cli.md"),
	e("exit.assertion", "check completed with remaining findings at or above the severity gate.", "Fix the findings, lower the policy gate, or add a dated exception. Exit 6 does not change the report contents.", "docs/check.md"),

	e("policy.missing-file", "The policy file is missing or unreadable.", "Pass --policy to a readable file. Empty --policy= is usage, not a missing file.", "docs/policy.md"),
	e("policy.malformed", "The policy file is empty or not a mapping.", "Provide a single YAML or JSON object with schema: composelens.policy.v0.", "docs/policy.md"),
	e("policy.missing-schema", "The policy file has no schema field.", "Set schema to composelens.policy.v0.", "docs/policy.md"),
	e("policy.unknown-schema", "The policy schema id is not composelens.policy.v0.", "Use schema: composelens.policy.v0. Other ids are rejected.", "docs/policy.md"),
	e("policy.unknown-field", "The policy file contains a field that is not in the schema.", "Remove unknown keys. Allowed top-level fields: schema, rules, exceptions, gate.", "docs/policy.md"),
	e("policy.unknown-rule", "A policy rule id is not CHK01–CHK06.", "Overlay only the fixed ruleset ids. Custom rule ids are not a policy engine.", "docs/policy.md"),
	e("policy.invalid-rule", "A policy rule overlay is invalid.", "enabled must be a boolean; severity and gate must be error, warning, or info.", "docs/policy.md"),
	e("policy.exception-date", "A policy exception date is missing, invalid, or not strictly in the future.", "Set expires to a future UTC date (YYYY-MM-DD). Past and today fail at load.", "docs/policy.md"),
	e("policy.duplicate-rule", "The same rule id appears more than once.", "List each CHK id at most once.", "docs/policy.md"),
	e("policy.duplicate-exception", "The same rule has more than one exception.", "Keep one exception per rule id.", "docs/policy.md"),
	e("policy.duplicate-field", "The policy mapping has a duplicate key.", "YAML/JSON duplicate keys are rejected before analysis.", "docs/policy.md"),
	e("policy.too-large", "The policy file exceeds the per-file byte bound.", "Keep the policy under 1 MiB. Split is not supported; this is untrusted input.", "docs/limits.md"),
	e("policy.invalid-encoding", "The policy file is not valid UTF-8.", "Save the file as UTF-8 without a conflicting encoding.", "docs/policy.md"),
	e("policy.too-deep", "The policy structure exceeds the YAML/JSON depth bound.", "Flatten the overlay. Depth 64 matches the Compose parser cap.", "docs/limits.md"),
	e("policy.too-many-nodes", "The policy structure exceeds the node bound.", "Reduce lists and nested objects. The cap is 50 000 nodes.", "docs/limits.md"),
	e("policy.unsupported-construct", "The policy YAML uses anchors, aliases, merge keys, or custom tags.", "Write plain mappings and lists only.", "docs/policy.md"),
	e("policy.multiple-documents", "The policy file contains more than one YAML document.", "Keep a single document.", "docs/policy.md"),
	e("policy.trailing-content", "The policy file has trailing content after the document.", "Remove extra tokens after the object.", "docs/policy.md"),

	e("redact.missing-file", "The redaction config is missing or unreadable.", "Pass --redact to a readable file, or add composelens.redact.yaml in the project directory.", "docs/redact.md"),
	e("redact.malformed", "The redaction config is empty or not a mapping.", "Provide a single YAML or JSON object with schema: composelens.redact.v0.", "docs/redact.md"),
	e("redact.missing-schema", "The redaction config has no schema field.", "Set schema to composelens.redact.v0.", "docs/redact.md"),
	e("redact.unknown-schema", "The redaction schema id is not composelens.redact.v0.", "Use schema: composelens.redact.v0.", "docs/redact.md"),
	e("redact.unknown-field", "The redaction config contains a field that is not in the schema.", "Allowed fields: schema, display, secretKeys, secretValues, allowKeys, allowValues.", "docs/redact.md"),
	e("redact.invalid", "A redaction config value is invalid.", "Use specific names or regexes; reject blanket .*; do not paste secret-shaped strings as added patterns.", "docs/redact.md"),
	e("redact.too-large", "The redaction config exceeds the per-file byte bound.", "Keep the file under 1 MiB.", "docs/limits.md"),
	e("redact.invalid-encoding", "The redaction config is not valid UTF-8.", "Save the file as UTF-8.", "docs/redact.md"),
	e("redact.too-deep", "The redaction config exceeds the depth bound.", "Flatten lists. Depth matches the Compose parser cap.", "docs/limits.md"),
	e("redact.too-many-nodes", "The redaction config exceeds the node bound.", "Reduce entries. Max 32 items per list.", "docs/limits.md"),
	e("redact.unsupported-construct", "The redaction YAML uses anchors, aliases, merge keys, or custom tags.", "Write plain mappings and lists only.", "docs/redact.md"),
	e("redact.multiple-documents", "The redaction config contains more than one YAML document.", "Keep a single document.", "docs/redact.md"),
	e("redact.trailing-content", "The redaction config has trailing content after the document.", "Remove extra tokens after the object.", "docs/redact.md"),
	e("redact.duplicate-field", "The redaction mapping has a duplicate key.", "Duplicate keys are rejected before analysis.", "docs/redact.md"),

	e("safety.input-too-large", "A file exceeds the per-file byte bound.", "Keep each input under 1 MiB. ComposeLens does not stream unbounded files.", "docs/limits.md"),
	e("safety.input-not-regular-file", "An input path is a device, FIFO, socket or pseudo-file (such as /proc/self/environ), not a regular file.", "Point -f, --env-file, include, extends and env_file at regular files. ComposeLens never opens special files, so a FIFO cannot block it and process state is never read.", "docs/limits.md"),
	e("safety.project-directory-missing", "The selected project directory does not exist or is not a directory.", "Pass an existing directory to --project-directory (or the Action input project-directory). Nothing is analyzed for a missing project.", "docs/cli.md"),
	e("safety.no-compose-file", "check found no Compose file in the project directory.", "Add compose.yaml (or compose.yml, docker-compose.yaml, docker-compose.yml), or name the file with -f. A gate never passes an empty project.", "docs/check.md"),
	e("safety.output-exists", "The output path already exists or is a symbolic link; ComposeLens does not overwrite it or write through it.", "Choose a new file name for doctor --bundle (or remove the old file yourself).", "docs/support.md"),
	e("safety.input-total-too-large", "The invocation exceeded the aggregate byte budget.", "Reduce Compose, env, policy, redaction, and engine-capture size. Unique paths share one 4 MiB budget.", "docs/limits.md"),
	e("safety.input-too-many-files", "The invocation exceeded the unique file-count budget.", "Stay under 256 unique charged paths.", "docs/limits.md"),
	e("safety.engine-output-too-large", "An engine stdout or stderr stream exceeded its bound.", "Reduce the selected input or engine output to fit the documented capture bound.", "docs/limits.md"),
	e("safety.yaml-too-deep", "YAML nesting exceeds the parser depth bound.", "Flatten the Compose file. Hostile depth is refused.", "docs/parser.md"),
	e("safety.yaml-alias-limit", "YAML alias expansion exceeded the bound.", "Remove excessive anchors/aliases.", "docs/parser.md"),
	e("safety.yaml-too-many-nodes", "YAML node count exceeded the bound.", "Reduce document size. The cap is 50 000 nodes.", "docs/parser.md"),
	e("safety.include-expansion-limit", "Include expansion exceeded the bound (256 included files per root file, repeated references counted).", "Remove repeated include references; include each file once. A file included twice per level grows exponentially.", "docs/limits.md"),
	e("safety.env-syntax", "An env file line is not valid env-file syntax (an unterminated quote or an invalid variable name); docker compose refuses it too.", "Fix the reported line: close the quote, or use only letters, digits and _ . - [ ] in names.", "docs/containerenv.md"),
	e("safety.env-unsupported", "An env file construct is accepted by the engine but not modeled by ComposeLens (an empty variable name).", "Remove or name the entry. ComposeLens refuses instead of guessing.", "docs/containerenv.md"),
	e("safety.parse-timeout", "Parsing exceeded the time bound.", "Simplify the document. Timeouts fail typed, they do not hang.", "docs/parser.md"),
	e("safety.yaml-malformed", "YAML/JSON is malformed.", "Fix syntax. Diagnostics do not echo file contents.", "docs/parser.md"),
	e("safety.invalid-encoding", "A loaded file is not valid UTF-8.", "Save as UTF-8.", "docs/parser.md"),
	e("safety.duplicate-mapping-key", "A YAML mapping has a duplicate key.", "Make keys unique. Duplicate keys are rejected.", "docs/parser.md"),
	e("safety.yaml-not-mapping", "The document root is not a mapping.", "Compose files must be a mapping at the root.", "docs/parser.md"),
}

var byID map[string]Entry

func init() {
	byID = make(map[string]Entry, len(catalog))
	for _, ent := range catalog {
		byID[ent.ID] = ent
	}
}

// Catalog returns the full diagnostics catalog in stable declaration order.
func Catalog() []Entry {
	out := make([]Entry, len(catalog))
	copy(out, catalog)
	return out
}

// LookupID returns a catalog entry by stable id.
func LookupID(id string) (Entry, bool) {
	ent, ok := byID[id]
	return ent, ok
}
