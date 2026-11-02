// SPDX-License-Identifier: Apache-2.0

package engineadapter

import "composelens/internal/evidence"

const (
	Schema = "composelens.engineadapter.v0"

	StateCaptured     = "captured"
	StateEngineAbsent = "engine-absent"
	StateEngineError  = "engine-error"
	StateUnsupported  = "unsupported"
	// StateSkipped: no engine command ran, by choice (--no-engine) or because
	// the selection needs the network (remote include without --allow-network).
	StateSkipped = "skipped"
)

// Request is a project/selection for `docker compose config`.
// The adapter never pulls images or starts containers.
type Request struct {
	ProjectDir string
	Files      []string
	EnvFiles   []string
	Profiles   []string
}

// Result is a typed engine capture. ConfigStdout is redacted or empty.
// A missing engine never yields a fabricated config.
type Result struct {
	Schema         string `json:"schema"`
	State          string `json:"state"`
	VersionCommand string `json:"versionCommand,omitempty"`
	Version        string `json:"version,omitempty"`
	ConfigCommand  string `json:"configCommand,omitempty"`
	ConfigStdout   string `json:"configStdout,omitempty"`
	ConfigStderr   string `json:"configStderr,omitempty"`
	ExitCode       int    `json:"exitCode"`
	Timestamp      string `json:"timestamp"`
	OutputDigest   string `json:"outputDigest,omitempty"`
	Detail         string `json:"detail,omitempty"`
	Evidence       string `json:"evidence"`
	Certainty      string `json:"certainty"`
	Disclaimer     string `json:"disclaimer"`
	Err            error  `json:"-"`
}

func emptyResult(ts string) Result {
	return Result{
		Schema:     Schema,
		Timestamp:  ts,
		Disclaimer: "engine adapter capture — not a differential; not fabricated config",
		Evidence:   evidence.Known,
		Certainty:  evidence.Proven,
	}
}
