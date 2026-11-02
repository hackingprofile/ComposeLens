// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"composelens/internal/evidence"
	"composelens/internal/redact"
	"composelens/internal/safety"
)

// MaxDetailBytes bounds the detection detail kept from a failing command.
const MaxDetailBytes = 160

type Info struct {
	State     string `json:"state"`
	Kind      string `json:"kind,omitempty"`
	Version   string `json:"version,omitempty"`
	Command   string `json:"command,omitempty"`
	Detail    string `json:"detail,omitempty"`
	Certainty string `json:"certainty"`
	// Err is a typed resource-bound refusal (engine output too large).
	Err error `json:"-"`
	// withheld holds the secret fragments removed from Detail; callers add
	// them to the output guard (GuardMaterial).
	withheld []string
}

// GuardMaterial returns the values withheld from detection metadata, so every
// output that carries this Info is guarded against them.
func (i Info) GuardMaterial() []string {
	return append([]string(nil), i.withheld...)
}

// Runner runs one detection command and returns its stdout.
type Runner func(ctx context.Context, name string, args ...string) (string, error)

// Detector runs version detection. Zero fields use the real subprocess and
// exec.LookPath.
type Detector struct {
	Run      Runner
	LookPath func(file string) (string, error)
}

func Detect() Info { return Detector{}.Detect() }

func (d Detector) Detect() Info {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	runner := d.Run
	if runner == nil {
		runner = run
	}
	lookPath := d.LookPath
	if lookPath == nil {
		lookPath = exec.LookPath
	}

	attempts := [][]string{
		{"docker", "compose", "version", "--short"},
		{"docker", "compose", "version"},
		{"docker-compose", "version", "--short"},
		{"docker-compose", "version"},
	}
	var last string
	var withheld []string
	for _, args := range attempts {
		out, err := runner(ctx, args[0], args[1:]...)
		if err != nil {
			if safety.IsResourceBound(err) {
				return Info{State: evidence.Unknown, Command: strings.Join(args, " "), Detail: "engine output exceeds declared bound", Certainty: evidence.Unknown, Err: err}
			}
			detail, frags := sanitizeDetail(err.Error())
			last = detail
			withheld = append(withheld, frags...)
			continue
		}
		ver := parseVersion(out)
		kind := "docker-compose-plugin"
		if args[0] == "docker-compose" {
			kind = "docker-compose"
		}
		if ver == "" {
			return Info{State: evidence.Unknown, Kind: kind, Command: strings.Join(args, " "), Detail: "version string not recognized", Certainty: evidence.Unknown, withheld: withheld}
		}
		return Info{State: evidence.Known, Kind: kind, Version: ver, Command: strings.Join(args, " "), Certainty: evidence.Proven, withheld: withheld}
	}
	if _, err := lookPath("docker"); err != nil {
		if _, err2 := lookPath("docker-compose"); err2 != nil {
			return Info{State: evidence.Absent, Detail: "docker CLI not found on PATH", Certainty: evidence.Proven, withheld: withheld}
		}
	}
	return Info{State: evidence.Unknown, Detail: last, Certainty: evidence.Unknown, withheld: withheld}
}

func run(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &safety.BoundBuffer{Max: safety.MaxEngineOutputBytes}
	stderr := &safety.BoundBuffer{Max: safety.MaxEngineOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	if stdout.Overflow() || stderr.Overflow() {
		return "", safety.NewParseError(safety.CodeEngineOutputTooLarge, "", "engine output exceeds declared bound")
	}
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return "", simpleError(msg)
	}
	return stdout.String(), nil
}

type simpleError string

func (e simpleError) Error() string { return string(e) }

// reVersion is the accepted version grammar: [v]MAJOR.MINOR[.PATCH] with an
// optional pre-release/build suffix. Anything else is not stored.
var reVersion = regexp.MustCompile(`^v?[0-9]{1,4}\.[0-9]{1,4}(\.[0-9]{1,6})?([-+][0-9A-Za-z][0-9A-Za-z.+-]{0,40})?$`)

// ValidVersion reports whether s matches the version grammar.
func ValidVersion(s string) bool {
	return len(s) <= 64 && reVersion.MatchString(s) && !redact.ContainsStrongToken(s)
}

// ParseVersion extracts a version from `docker compose version` output, or
// "" when the text does not match the version grammar.
func ParseVersion(out string) string { return parseVersion(out) }

func parseVersion(out string) string {
	s := strings.TrimSpace(out)
	if s == "" {
		return ""
	}
	first := strings.SplitN(s, "\n", 2)[0]
	first = strings.TrimSpace(first)
	first = strings.TrimPrefix(first, "Docker Compose version ")
	first = strings.TrimPrefix(first, "docker-compose version ")
	first = strings.TrimSpace(first)
	if i := strings.IndexByte(first, ','); i > 0 { // docker-compose 1.x: "1.29.2, build 5becea4c"
		first = first[:i]
	}
	if !ValidVersion(first) {
		return ""
	}
	return first
}

// sanitizeDetail keeps the first line of a failing command's message,
// withholds recognized tokens, credential pairs and secret-shaped words, and
// bounds the result. It returns the withheld fragments.
func sanitizeDetail(msg string) (string, []string) {
	line := strings.TrimSpace(strings.SplitN(strings.TrimSpace(msg), "\n", 2)[0])
	var withheld []string
	words := strings.Fields(line)
	for i, w := range words {
		if k, v, ok := cutPair(w); ok && v != "" && (redact.IsSecretKey(k) || redact.LooksLikeSecret(v) || redact.ContainsStrongToken(v)) {
			withheld = append(withheld, v)
			words[i] = k + w[len(k):len(k)+1] + redact.TokenRedacted
			continue
		}
		if redact.ContainsStrongToken(w) || redact.LooksLikeSecret(w) {
			withheld = append(withheld, w)
			words[i] = redact.TokenRedacted
		}
	}
	out := redact.ScrubStrongTokens(strings.Join(words, " "))
	if len(out) > MaxDetailBytes {
		cut := MaxDetailBytes - len("…")
		for cut > 0 && !utf8.RuneStart(out[cut]) {
			cut--
		}
		out = out[:cut] + "…"
	}
	return out, withheld
}

func cutPair(w string) (string, string, bool) {
	i := strings.IndexAny(w, "=:")
	if i <= 0 {
		return "", "", false
	}
	return w[:i], w[i+1:], true
}
