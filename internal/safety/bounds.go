// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"errors"
	"fmt"
	"time"

	"composelens/internal/redact"
)

// Resource bounds for the Compose parser/loader. Ordinary Compose files are
// kilobytes and a handful of mapping levels; these caps refuse hostile input
// without rejecting documented Compose.
const (
	MaxFileBytes         = 1 << 20 // 1 MiB per file
	MaxTotalBytes        = 4 << 20 // 4 MiB across one invocation's charged input
	MaxTotalFiles        = 256     // unique charged paths per invocation
	MaxEngineOutputBytes = 4 << 20 // 4 MiB per engine stdout or stderr stream
	MaxYAMLDepth         = 64
	MaxAliasExpansion    = 4096
	MaxYAMLNodes         = 50_000
	// MaxIncludeExpansions bounds the include files expanded per root file,
	// counting every repeated reference, so a DAG that includes the same file
	// twice per level cannot grow work or output exponentially.
	MaxIncludeExpansions = 256
	DefaultParseTimeout  = 2 * time.Second
)

type Code string

const (
	CodeFileTooLarge         Code = "input-too-large"
	CodeTotalTooLarge        Code = "input-total-too-large"
	CodeTooManyFiles         Code = "input-too-many-files"
	CodeEngineOutputTooLarge Code = "engine-output-too-large"
	CodeTooDeep              Code = "yaml-too-deep"
	CodeAliasLimit           Code = "yaml-alias-limit"
	CodeTooManyNodes         Code = "yaml-too-many-nodes"
	CodeTimeout              Code = "parse-timeout"
	CodeMalformed            Code = "yaml-malformed"
	CodeEncoding             Code = "invalid-encoding"
	CodeDuplicateKey         Code = "duplicate-mapping-key"
	CodeNotMapping           Code = "yaml-not-mapping"
	CodeIncludeExpansion     Code = "include-expansion-limit"
	CodeEnvSyntax            Code = "env-syntax"
	CodeEnvUnsupported       Code = "env-unsupported"
	// CodeNotRegularFile refuses devices, FIFOs, sockets and pseudo-file
	// systems such as /proc: reading them can block forever or dump process
	// state that is not project input.
	CodeNotRegularFile Code = "input-not-regular-file"
	// CodeProjectMissing: the selected project directory does not exist.
	CodeProjectMissing Code = "project-directory-missing"
	// CodeNoComposeFile: check found no Compose file to check.
	CodeNoComposeFile Code = "no-compose-file"
	// CodeOutputExists: an output path that must be new already exists (or is a
	// symlink); nothing is overwritten.
	CodeOutputExists Code = "output-exists"
)

// ParseError is a typed, secret-safe parser/loader diagnostic.
type ParseError struct {
	Code   Code
	Path   string
	Detail string
}

func (e *ParseError) Error() string {
	if e == nil {
		return "parse: unknown"
	}
	path := displayPath(e.Path)
	if path == "" {
		return fmt.Sprintf("parse: %s (%s)", e.Detail, e.Code)
	}
	return fmt.Sprintf("parse %s: %s (%s)", path, e.Detail, e.Code)
}

func displayPath(path string) string {
	if path == "" {
		return ""
	}
	if redact.LooksLikeSecret(path) {
		return "<redacted>"
	}
	return path
}

// IsResourceBound reports whether err is an aggregate, per-file, file-count,
// or engine-output cap failure. Callers must stop further analysis.
func IsResourceBound(err error) bool {
	switch CodeOf(err) {
	case CodeFileTooLarge, CodeTotalTooLarge, CodeTooManyFiles, CodeEngineOutputTooLarge:
		return true
	default:
		return false
	}
}

func NewParseError(code Code, path, detail string) *ParseError {
	return &ParseError{Code: code, Path: path, Detail: redactDiagnostic(detail)}
}

func CodeOf(err error) Code {
	var pe *ParseError
	if errors.As(err, &pe) && pe != nil {
		return pe.Code
	}
	return ""
}

func redactDiagnostic(detail string) string {
	if detail == "" {
		return ""
	}
	if redact.LooksLikeSecret(detail) {
		return "refused to echo input in diagnostic"
	}
	return detail
}

// GuardMessage fails closed if a diagnostic would contain a known secret.
func GuardMessage(msg string, secrets []string) error {
	return Guard([]byte(msg), secrets)
}

// IsRefusal reports whether err is a typed parser or safety refusal (any
// ParseError code). Such an error below include or extends fails the run
// exactly as it does for a root file.
func IsRefusal(err error) bool {
	return CodeOf(err) != ""
}
