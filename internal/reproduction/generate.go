// SPDX-License-Identifier: Apache-2.0

package reproduction

import (
	"fmt"
	"strings"

	"composelens/internal/redact"
)

const (
	Schema     = "composelens.reproduce.v0"
	DefaultBin = "docker"
)

// Input is the analysis selection ComposeLens used to build its model.
// Values are files and flags only — never raw secret material.
type Input struct {
	Binary     string
	ProjectDir string
	Files      []string
	EnvFiles   []string
	Profiles   []string
}

// Command is the exact docker compose config invocation.
type Command struct {
	Argv []string `json:"argv"`
	Line string   `json:"command"`
}

// Generate returns a deterministic, minimal `docker compose … config` command.
// Flag order matches the engine adapter: project-directory, -f, --env-file, --profile, config.
func Generate(in Input) Command {
	bin := strings.TrimSpace(in.Binary)
	if bin == "" {
		bin = DefaultBin
	}
	argv := []string{bin, "compose"}
	if strings.TrimSpace(in.ProjectDir) != "" {
		argv = append(argv, "--project-directory", in.ProjectDir)
	}
	for _, f := range in.Files {
		if strings.TrimSpace(f) == "" {
			continue
		}
		argv = append(argv, "-f", f)
	}
	for _, e := range in.EnvFiles {
		if strings.TrimSpace(e) == "" {
			continue
		}
		argv = append(argv, "--env-file", e)
	}
	for _, p := range in.Profiles {
		if strings.TrimSpace(p) == "" {
			continue
		}
		argv = append(argv, "--profile", p)
	}
	argv = append(argv, "config")
	return Command{Argv: append([]string{}, argv...), Line: FormatLine(argv)}
}

// FormatLine quotes argv for POSIX-shell copy-paste. Live validation executes
// Argv, not the shell line. The copy-paste line is not a cmd.exe/PowerShell form.
func FormatLine(argv []string) string {
	parts := make([]string, 0, len(argv))
	for _, a := range argv {
		parts = append(parts, Quote(a))
	}
	return strings.Join(parts, " ")
}

// Quote emits a POSIX-safe token. Conservative safe bytes [A-Za-z0-9_@%+=:,./-]
// may be bare; every other token is single-quoted, with ' rendered as '\”.
// An empty token becomes ”.
func Quote(s string) string {
	if s == "" {
		return "''"
	}
	if !needsQuote(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

func needsQuote(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			continue
		}
		switch c {
		case '_', '@', '%', '+', '=', ':', ',', '.', '/', '-':
			continue
		}
		return true
	}
	return false
}

// RejectSecrets fails if a known secret would appear in argv or the formatted line.
func RejectSecrets(cmd Command, secrets []string) error {
	blob := cmd.Line + "\n" + strings.Join(cmd.Argv, "\n")
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(blob, s) {
			return fmt.Errorf("reproduction command would inline a secret")
		}
	}
	if redact.LooksLikeSecret(blob) && !filesOnlySecretShape(cmd) {
		return fmt.Errorf("reproduction command looks secret-shaped")
	}
	return nil
}

// filesOnlySecretShape allows a compose *path* that itself looks like a secret
// to be classified by LooksLikeSecret on the whole line; RejectSecrets still
// catches inlined values via the secrets list. A command that only references
// ordinary flags is not secret-shaped even if LooksLikeSecret is conservative
// on the concatenated blob.
func filesOnlySecretShape(cmd Command) bool {
	for i := 0; i < len(cmd.Argv); i++ {
		a := cmd.Argv[i]
		switch a {
		case "docker", "compose", "config", "--project-directory", "-f", "--file", "--env-file", "--profile":
			continue
		}
		if strings.HasPrefix(a, "-") {
			continue
		}
		if redact.LooksLikeSecret(a) {
			return false
		}
	}
	return true
}
