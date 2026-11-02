// SPDX-License-Identifier: Apache-2.0

package engineadapter

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"composelens/internal/digest"
	"composelens/internal/engine"
	"composelens/internal/evidence"
	"composelens/internal/safety"
)

const defaultTimeout = 15 * time.Second

type ExecResult struct {
	Stdout   string
	Stderr   string
	Exit     int
	Err      error
	Overflow bool
}

type Runner struct {
	LookPath func(file string) (string, error)
	Exec     func(ctx context.Context, name string, args []string) ExecResult
	Now      func() time.Time
	Budget   *safety.Budget
}

func DefaultRunner() Runner {
	return Runner{
		LookPath: exec.LookPath,
		Exec:     realExec,
		Now:      time.Now,
	}
}

func (r Runner) WithBudget(b *safety.Budget) Runner {
	r.Budget = b
	return r
}

func (r Runner) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}

func (r Runner) lookPath(file string) (string, error) {
	if r.LookPath != nil {
		return r.LookPath(file)
	}
	return exec.LookPath(file)
}

func (r Runner) exec(ctx context.Context, name string, args []string) ExecResult {
	if r.Exec != nil {
		return r.Exec(ctx, name, args)
	}
	return realExec(ctx, name, args)
}

// Capture runs `docker compose version` then `docker compose … config`.
// It never fabricates config. Docker-absent is a typed result.
func (r Runner) Capture(ctx context.Context, req Request) Result {
	ts := r.now().UTC().Format(time.RFC3339)
	out := emptyResult(ts)
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultTimeout)
		defer cancel()
	}

	name, plugin := r.resolveBinary()
	if name == "" {
		out.State = StateEngineAbsent
		out.Detail = "docker CLI not found on PATH"
		out.Evidence = evidence.Absent
		return out
	}

	verArgs := versionArgs(plugin)
	out.VersionCommand = formatCmd(name, verArgs)
	ver := r.exec(ctx, name, verArgs)
	if err := r.retainEngine(ver); err != nil {
		out.State = StateEngineError
		out.Err = err
		out.Detail = err.Error()
		out.ExitCode = ver.Exit
		return failClosed(out)
	}
	if ver.Err != nil && ver.Exit == 0 {
		out.State = StateEngineError
		out.ExitCode = ver.Exit
		out.Detail = "engine version command failed"
		out.ConfigStderr = redactText(ver.Stderr)
		if out.ConfigStderr == "" {
			out.ConfigStderr = redactText(ver.Err.Error())
		}
		return failClosed(out)
	}
	if ver.Exit != 0 {
		out.State = StateEngineError
		out.ExitCode = ver.Exit
		out.Detail = "engine version command exited nonzero"
		out.ConfigStderr = redactText(ver.Stderr)
		return failClosed(out)
	}
	out.Version = parseVersion(ver.Stdout)

	cfgArgs := configArgs(plugin, req)
	out.ConfigCommand = formatCmd(name, cfgArgs)
	cfg := r.exec(ctx, name, cfgArgs)
	out.ExitCode = cfg.Exit
	if err := r.retainEngine(cfg); err != nil {
		out.State = StateEngineError
		out.Err = err
		out.Detail = err.Error()
		return failClosed(out)
	}
	redactedOut, secrets := RedactEngineOutput(cfg.Stdout)
	redactedErr, errSecrets := RedactEngineOutput(cfg.Stderr)
	secrets = append(secrets, errSecrets...)
	if err := safety.Guard([]byte(redactedOut+"\n"+redactedErr), secrets); err != nil {
		out.State = StateEngineError
		out.Detail = "fail-closed: refuse to retain engine output"
		out.ConfigStdout = ""
		out.ConfigStderr = ""
		out.OutputDigest = ""
		return out
	}
	if cfg.Exit != 0 || cfg.Err != nil {
		out.State = StateEngineError
		out.Detail = "engine config command exited nonzero"
		out.ConfigStderr = redactedErr
		out.ConfigStdout = ""
		return out
	}
	out.State = StateCaptured
	out.ConfigStdout = redactedOut
	out.ConfigStderr = redactedErr
	out.OutputDigest = digest.Bytes([]byte(redactedOut))
	return out
}

// Unsupported reports a typed refusal for verbs this adapter does not run
// (anything other than version/config). It never invents config.
func Unsupported(verb string) Result {
	out := emptyResult(time.Now().UTC().Format(time.RFC3339))
	out.State = StateUnsupported
	out.Detail = "adapter supports docker compose version and config only; refused " + redactText(verb)
	out.Evidence = evidence.Unsupported
	return out
}

func (r Runner) resolveBinary() (name string, plugin bool) {
	if _, err := r.lookPath("docker"); err == nil {
		return "docker", true
	}
	if _, err := r.lookPath("docker-compose"); err == nil {
		return "docker-compose", false
	}
	return "", false
}

func versionArgs(plugin bool) []string {
	if plugin {
		return []string{"compose", "version"}
	}
	return []string{"version"}
}

func configArgs(plugin bool, req Request) []string {
	var args []string
	if plugin {
		args = append(args, "compose")
	}
	if req.ProjectDir != "" {
		args = append(args, "--project-directory", req.ProjectDir)
	}
	for _, f := range req.Files {
		args = append(args, "-f", f)
	}
	for _, e := range req.EnvFiles {
		args = append(args, "--env-file", e)
	}
	for _, p := range req.Profiles {
		args = append(args, "--profile", p)
	}
	args = append(args, "config")
	return args
}

func formatCmd(name string, args []string) string {
	return strings.TrimSpace(name + " " + strings.Join(args, " "))
}

// parseVersion keeps only text that matches the shared version grammar, so
// token-shaped or oversized version output is never retained.
func parseVersion(out string) string {
	return engine.ParseVersion(out)
}

func failClosed(out Result) Result {
	out.ConfigStdout = ""
	return out
}

func (r Runner) retainEngine(er ExecResult) error {
	if er.Overflow || safety.IsResourceBound(er.Err) || len(er.Stdout) > safety.MaxEngineOutputBytes || len(er.Stderr) > safety.MaxEngineOutputBytes {
		if er.Err != nil && safety.IsResourceBound(er.Err) {
			return er.Err
		}
		return safety.NewParseError(safety.CodeEngineOutputTooLarge, "", "engine output exceeds declared bound")
	}
	if err := r.Budget.ChargeStream(len(er.Stdout)); err != nil {
		return err
	}
	return r.Budget.ChargeStream(len(er.Stderr))
}

func realExec(ctx context.Context, name string, args []string) ExecResult {
	cmd := exec.CommandContext(ctx, name, args...)
	stdout := &safety.BoundBuffer{Max: safety.MaxEngineOutputBytes}
	stderr := &safety.BoundBuffer{Max: safety.MaxEngineOutputBytes}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()
	exit := 0
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			exit = ee.ExitCode()
		} else {
			exit = -1
		}
	}
	if stdout.Overflow() || stderr.Overflow() {
		return ExecResult{
			Overflow: true,
			Exit:     exit,
			Err:      safety.NewParseError(safety.CodeEngineOutputTooLarge, "", "engine output exceeds declared bound"),
		}
	}
	return ExecResult{Stdout: stdout.String(), Stderr: stderr.String(), Exit: exit, Err: err}
}

// Skipped reports a capture that ran no engine command: by choice
// (--no-engine) or because the selection needs the network.
func Skipped(reason string) Result {
	out := emptyResult(time.Now().UTC().Format(time.RFC3339))
	out.State = StateSkipped
	out.Detail = reason
	out.Evidence = evidence.Unknown
	return out
}
