// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"

	"composelens/internal/redact"
	"composelens/internal/version"
)

type Options struct {
	ProjectDirectory string
	Files            []string
	EnvFiles         []string
	Profiles         []string
	LeftProfiles     []string
	RightProfiles    []string
	LeftEnvFiles     []string
	RightEnvFiles    []string
	JSON             bool
	SARIF            bool
	GitHub           bool
	HTML             bool
	All              bool
	NoEngine         bool
	AllowNetwork     bool
	AllowShortSecret []string
	Help             bool
	Command          string
	Target           string
	Policy           string
	Redact           string
	Bundle           string
}

// shortSecretCommands are the commands whose output can carry project values,
// so a short collected secret refuses them and --allow-short-secret applies.
var shortSecretCommands = map[string]struct{}{
	"inspect": {}, "explain": {}, "diff": {}, "check": {}, "differential": {}, "report": {},
}

var (
	projectCommands = map[string]struct{}{
		"doctor": {}, "inspect": {}, "explain": {}, "diff": {},
		"check": {}, "differential": {}, "reproduce": {}, "report": {},
	}
	jsonCommands = map[string]struct{}{
		"version": {}, "doctor": {}, "inspect": {}, "explain": {}, "diff": {},
		"check": {}, "differential": {}, "reproduce": {}, "report": {}, "help": {},
	}
	knownCommands = map[string]struct{}{
		"version": {}, "doctor": {}, "inspect": {}, "explain": {}, "diff": {},
		"check": {}, "differential": {}, "reproduce": {}, "report": {}, "help": {},
	}
)

func ParseArgs(args []string) (Options, error) {
	var opt Options
	ended := false
	i := 0
	for i < len(args) {
		a := args[i]
		if !ended && a == "--" {
			ended = true
			i++
			continue
		}
		if ended || !isFlagToken(a) {
			if err := takePositional(&opt, a); err != nil {
				return opt, err
			}
			i++
			continue
		}
		if a == "-h" || a == "--help" {
			opt.Help = true
			i++
			continue
		}
		if a == "--json" {
			opt.JSON = true
			i++
			continue
		}
		if a == "--sarif" {
			opt.SARIF = true
			i++
			continue
		}
		if a == "--github" {
			opt.GitHub = true
			i++
			continue
		}
		if a == "--bundle" {
			v, n, err := consumeValue(args, i, "--bundle")
			if err != nil {
				return opt, err
			}
			opt.Bundle = v
			i = n
			continue
		}
		if strings.HasPrefix(a, "--bundle=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--bundle="), "--bundle")
			if err != nil {
				return opt, err
			}
			opt.Bundle = v
			i++
			continue
		}
		if a == "--html" {
			opt.HTML = true
			i++
			continue
		}
		if a == "--all" {
			opt.All = true
			i++
			continue
		}
		if a == "--no-engine" {
			opt.NoEngine = true
			i++
			continue
		}
		if a == "--allow-network" {
			opt.AllowNetwork = true
			i++
			continue
		}
		if a == "--allow-short-secret" {
			v, n, err := consumeValue(args, i, "--allow-short-secret")
			if err != nil {
				return opt, err
			}
			opt.AllowShortSecret = append(opt.AllowShortSecret, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--allow-short-secret=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--allow-short-secret="), "--allow-short-secret")
			if err != nil {
				return opt, err
			}
			opt.AllowShortSecret = append(opt.AllowShortSecret, v)
			i++
			continue
		}
		if a == "--policy" {
			v, n, err := consumeValue(args, i, "--policy")
			if err != nil {
				return opt, err
			}
			opt.Policy = v
			i = n
			continue
		}
		if strings.HasPrefix(a, "--policy=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--policy="), "--policy")
			if err != nil {
				return opt, err
			}
			opt.Policy = v
			i++
			continue
		}
		if a == "--redact" {
			v, n, err := consumeValue(args, i, "--redact")
			if err != nil {
				return opt, err
			}
			opt.Redact = v
			i = n
			continue
		}
		if strings.HasPrefix(a, "--redact=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--redact="), "--redact")
			if err != nil {
				return opt, err
			}
			opt.Redact = v
			i++
			continue
		}
		if a == "--project-directory" {
			v, n, err := consumeValue(args, i, "--project-directory")
			if err != nil {
				return opt, err
			}
			opt.ProjectDirectory = v
			i = n
			continue
		}
		if strings.HasPrefix(a, "--project-directory=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--project-directory="), "--project-directory")
			if err != nil {
				return opt, err
			}
			opt.ProjectDirectory = v
			i++
			continue
		}
		if a == "-f" || a == "--file" {
			v, n, err := consumeValue(args, i, a)
			if err != nil {
				return opt, err
			}
			opt.Files = append(opt.Files, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--file=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--file="), "--file")
			if err != nil {
				return opt, err
			}
			opt.Files = append(opt.Files, v)
			i++
			continue
		}
		if a == "--env-file" {
			v, n, err := consumeValue(args, i, "--env-file")
			if err != nil {
				return opt, err
			}
			opt.EnvFiles = append(opt.EnvFiles, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--env-file=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--env-file="), "--env-file")
			if err != nil {
				return opt, err
			}
			opt.EnvFiles = append(opt.EnvFiles, v)
			i++
			continue
		}
		if a == "--profile" {
			v, n, err := consumeValue(args, i, "--profile")
			if err != nil {
				return opt, err
			}
			opt.Profiles = append(opt.Profiles, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--profile=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--profile="), "--profile")
			if err != nil {
				return opt, err
			}
			opt.Profiles = append(opt.Profiles, v)
			i++
			continue
		}
		if a == "--left-profile" {
			v, n, err := consumeValue(args, i, "--left-profile")
			if err != nil {
				return opt, err
			}
			opt.LeftProfiles = append(opt.LeftProfiles, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--left-profile=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--left-profile="), "--left-profile")
			if err != nil {
				return opt, err
			}
			opt.LeftProfiles = append(opt.LeftProfiles, v)
			i++
			continue
		}
		if a == "--right-profile" {
			v, n, err := consumeValue(args, i, "--right-profile")
			if err != nil {
				return opt, err
			}
			opt.RightProfiles = append(opt.RightProfiles, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--right-profile=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--right-profile="), "--right-profile")
			if err != nil {
				return opt, err
			}
			opt.RightProfiles = append(opt.RightProfiles, v)
			i++
			continue
		}
		if a == "--left-env-file" {
			v, n, err := consumeValue(args, i, "--left-env-file")
			if err != nil {
				return opt, err
			}
			opt.LeftEnvFiles = append(opt.LeftEnvFiles, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--left-env-file=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--left-env-file="), "--left-env-file")
			if err != nil {
				return opt, err
			}
			opt.LeftEnvFiles = append(opt.LeftEnvFiles, v)
			i++
			continue
		}
		if a == "--right-env-file" {
			v, n, err := consumeValue(args, i, "--right-env-file")
			if err != nil {
				return opt, err
			}
			opt.RightEnvFiles = append(opt.RightEnvFiles, v)
			i = n
			continue
		}
		if strings.HasPrefix(a, "--right-env-file=") {
			v, err := equalsValue(strings.TrimPrefix(a, "--right-env-file="), "--right-env-file")
			if err != nil {
				return opt, err
			}
			opt.RightEnvFiles = append(opt.RightEnvFiles, v)
			i++
			continue
		}
		return opt, fmt.Errorf("unknown flag %s", redact.DiagnosticLabel(redact.FlagName(a)))
	}
	if err := validateFlags(opt); err != nil {
		return opt, err
	}
	return opt, nil
}

func isFlagToken(s string) bool {
	return strings.HasPrefix(s, "-")
}

func takePositional(opt *Options, a string) error {
	if opt.Command == "" {
		opt.Command = a
		return nil
	}
	if opt.Command == "explain" && opt.Target == "" {
		opt.Target = a
		return nil
	}
	return fmt.Errorf("unexpected argument %s", redact.DiagnosticLabel(a))
}

func consumeValue(args []string, i int, flag string) (string, int, error) {
	if i+1 >= len(args) || looksLikeFlag(args[i+1]) {
		return "", i, fmt.Errorf("missing value for %s", flag)
	}
	v := args[i+1]
	if strings.TrimSpace(v) == "" {
		return "", i, fmt.Errorf("missing value for %s", flag)
	}
	return v, i + 2, nil
}

func equalsValue(raw, flag string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return "", fmt.Errorf("missing value for %s", flag)
	}
	return raw, nil
}

func looksLikeFlag(s string) bool {
	if s == "" || s == "-" {
		return false
	}
	return strings.HasPrefix(s, "-")
}

func validateFlags(opt Options) error {
	cmd := opt.Command
	if cmd == "" || cmd == "help" {
		return nil
	}
	if _, known := knownCommands[cmd]; !known {
		return nil
	}
	_, project := projectCommands[cmd]
	_, jsonOK := jsonCommands[cmd]
	if opt.JSON && !jsonOK {
		return fmt.Errorf("--json is not valid with %s", cmd)
	}
	if opt.SARIF && cmd != "check" {
		return fmt.Errorf("--sarif is only valid with check")
	}
	if opt.GitHub && cmd != "check" {
		return fmt.Errorf("--github is only valid with check")
	}
	if opt.Bundle != "" && cmd != "doctor" {
		return fmt.Errorf("--bundle is only valid with doctor")
	}
	if opt.JSON && opt.Bundle != "" {
		return fmt.Errorf("--json and --bundle are mutually exclusive")
	}
	if opt.HTML && cmd != "report" {
		return fmt.Errorf("--html is only valid with report")
	}
	if opt.HTML && opt.JSON {
		return fmt.Errorf("--json and --html are mutually exclusive")
	}
	if opt.Policy != "" && cmd != "check" {
		return fmt.Errorf("--policy is only valid with check")
	}
	if opt.Redact != "" && !project {
		return fmt.Errorf("--redact is not valid with %s", cmd)
	}
	if opt.All && cmd != "explain" {
		return fmt.Errorf("--all is only valid with explain")
	}
	if opt.NoEngine && cmd != "report" {
		return fmt.Errorf("--no-engine is only valid with report")
	}
	if opt.AllowNetwork && cmd != "report" && cmd != "differential" {
		return fmt.Errorf("--allow-network is only valid with report and differential")
	}
	if opt.NoEngine && opt.AllowNetwork {
		return fmt.Errorf("--no-engine and --allow-network are mutually exclusive")
	}
	if len(opt.AllowShortSecret) > 0 {
		if _, ok := shortSecretCommands[cmd]; !ok {
			return fmt.Errorf("--allow-short-secret is only valid with inspect, explain, diff, check, differential and report")
		}
		for _, k := range opt.AllowShortSecret {
			if k == "" || strings.TrimSpace(k) != k || strings.ContainsAny(k, "*?[]{}\\ \t,;") {
				return fmt.Errorf("--allow-short-secret takes one exact key name (no wildcards, lists or spaces)")
			}
		}
	}
	if opt.ProjectDirectory != "" && !project {
		return fmt.Errorf("--project-directory is not valid with %s", cmd)
	}
	if len(opt.Files) > 0 && !project {
		return fmt.Errorf("--file is not valid with %s", cmd)
	}
	if len(opt.EnvFiles) > 0 && !project {
		return fmt.Errorf("--env-file is not valid with %s", cmd)
	}
	if len(opt.Profiles) > 0 && !project {
		return fmt.Errorf("--profile is not valid with %s", cmd)
	}
	if len(opt.LeftProfiles) > 0 && cmd != "diff" {
		return fmt.Errorf("--left-profile is not valid with %s", cmd)
	}
	if len(opt.RightProfiles) > 0 && cmd != "diff" {
		return fmt.Errorf("--right-profile is not valid with %s", cmd)
	}
	if len(opt.LeftEnvFiles) > 0 && cmd != "diff" {
		return fmt.Errorf("--left-env-file is not valid with %s", cmd)
	}
	if len(opt.RightEnvFiles) > 0 && cmd != "diff" {
		return fmt.Errorf("--right-env-file is not valid with %s", cmd)
	}
	return nil
}

var futureCommands = map[string]struct{}{}

func IsFutureCommand(cmd string) bool {
	_, ok := futureCommands[cmd]
	return ok
}

func Usage() string {
	return fmt.Sprintf(`composelens — secret-safe Compose source inspection (%s)

Usage:
  composelens [flags] <command>
  composelens -- <command> [operands]

Commands (%s):
  doctor    Platform, engine detection, inputs, feature support
  inspect   Source-level files, services, env, interpolation, merge, and profiles (not provenance)
  explain   Single-target account, or whole-model graph with --all
  diff      Effective-config delta between two selections over the same files
  check        Fixed ruleset over the effective model (human, JSON, SARIF, or GitHub)
  differential Internal model vs live docker compose config (honest divergences)
  reproduce    Exact docker compose config command that recreates the modeled configuration
  report       JSON data package (--json) or interactive offline HTML (--html); human reserved
  version      Print version (--json only; no project/selection flags)

Flags (see docs/cli.md for the per-command matrix):
  --project-directory <dir>  Project-reading commands only. Empty value is usage.
  -f, --file <path>          Repeatable. Disables default discovery.
  --env-file <path>          Repeatable. Replaces project .env and COMPOSE_ENV_FILES.
  --profile <name>           Repeatable. Active Compose profiles; overrides COMPOSE_PROFILES.
  --left-profile <name>      Repeatable. Diff only.
  --right-profile <name>     Repeatable. Diff only.
  --left-env-file <path>     Repeatable. Diff only.
  --right-env-file <path>    Repeatable. Diff only.
  --json                     Stable JSON on stdout
  --html                     Self-contained interactive HTML report on stdout (report only)
  --sarif                    SARIF 2.1.0 on stdout (check only; not an upload)
  --github                   GitHub workflow annotations on stdout (check only; not a CI run)
  --bundle <path>            Diagnostic support bundle (doctor only; no project source values)
  --policy <file>            Schema-validated policy overlay (check only)
  --redact <file>            Schema-validated redaction overlay (project-reading commands)
  --all                      Whole-model provenance graph (explain only)
  --no-engine                Run no docker command; the differential section is skipped (report only)
  --allow-network            Let the local engine capture resolve remote includes over the network (report, differential)
  --allow-short-secret <KEY> Repeatable, exact key name. Accept a secret value under KEY shorter than 6 bytes; it stays withheld
  --                         End of flags; next token is the command (or explain target)
  -h, --help

Value flags: missing, empty (--x=), or a following flag as the value is usage (exit 2) before any work.
Inapplicable flags for the command are usage (exit 2) before any work.

Exit codes: 0 success, 2 usage, 3 input, 4 safety, 5 unsupported, 6 assertion, 1 internal.
See docs/cli.md.
`, version.Version, version.Version)
}
