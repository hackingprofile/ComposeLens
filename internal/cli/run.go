// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"

	"composelens/internal/check"
	"composelens/internal/ci"
	"composelens/internal/composeparse"
	"composelens/internal/containerenv"
	"composelens/internal/diag"
	"composelens/internal/diff"
	"composelens/internal/differential"
	"composelens/internal/discover"
	"composelens/internal/engine"
	"composelens/internal/engineadapter"
	"composelens/internal/enginecap"
	"composelens/internal/envsrc"
	"composelens/internal/evidence"
	"composelens/internal/exitcode"
	"composelens/internal/explain"
	"composelens/internal/extends"
	"composelens/internal/idpath"
	"composelens/internal/include"
	"composelens/internal/interp"
	"composelens/internal/merge"
	"composelens/internal/normalize"
	"composelens/internal/paths"
	"composelens/internal/policy"
	"composelens/internal/profiles"
	"composelens/internal/provgraph"
	"composelens/internal/redact"
	"composelens/internal/report"
	"composelens/internal/reproduction"
	"composelens/internal/safety"
	"composelens/internal/version"
)

// writeErr writes a diagnostic. Recognized vendor tokens (in argv, paths or OS
// errors) are withheld before anything reaches stderr.
func writeErr(w io.Writer, format string, args ...any) {
	for i, arg := range args {
		if err, ok := arg.(error); ok {
			args[i] = redact.EscapeControls(err.Error())
		}
	}
	_, _ = io.WriteString(w, redact.ScrubStrongTokens(fmt.Sprintf(format, args...)))
}

// writeText is writeErr for human report text: every string argument is data
// from the project, so its control characters are shown escaped and an
// embedded newline cannot start a line (such as a GitHub "::error::" command).
func writeText(w io.Writer, format string, args ...any) {
	safe := make([]any, len(args))
	for i, a := range args {
		switch v := a.(type) {
		case string:
			safe[i] = redact.EscapeControls(v)
		case []string:
			cp := make([]string, len(v))
			for j, s := range v {
				cp[j] = redact.EscapeControls(s)
			}
			safe[i] = cp
		default:
			safe[i] = a
		}
	}
	writeErr(w, format, safe...)
}

type Runtime struct {
	Stdout           io.Writer
	Stderr           io.Writer
	Environ          []string
	Cwd              string
	Detect           func() engine.Info
	NewFingerprinter func() (*redact.Fingerprinter, error)
	// EngineRunner supplies the engine adapter (nil: the real docker CLI).
	EngineRunner func() engineadapter.Runner

	// opt is the parsed invocation; short lists the short secret values the
	// command collected. Both are set while a command runs.
	opt             Options
	short           []shortSource
	publicRevisions []string
}

func Run(args []string, stdout, stderr io.Writer, environ []string) int {
	cwd, err := os.Getwd()
	if err != nil {
		writeErr(stderr, "composelens: %v\n", err)
		return exitcode.Internal
	}
	rt := Runtime{Stdout: stdout, Stderr: stderr, Environ: environ, Cwd: cwd, Detect: engine.Detect}
	return rt.Run(args)
}

func (rt Runtime) Run(args []string) (code int) {
	defer redact.Reset()
	defer func() {
		if code == exitcode.Internal {
			writeCrashGuidance(rt.Stderr)
		}
	}()
	opt, err := ParseArgs(args)
	if err != nil {
		return rt.writeUsage(err.Error(), false)
	}
	if opt.Help || opt.Command == "help" || (opt.Command == "" && opt.Help) {
		return rt.emit([]byte(Usage()), nil)
	}
	if opt.Command == "" {
		return rt.writeUsage("missing command", true)
	}
	if opt.SARIF && opt.Command != "check" {
		return rt.writeUsage("--sarif is only valid with check", true)
	}
	if opt.GitHub && opt.Command != "check" {
		return rt.writeUsage("--github is only valid with check", true)
	}
	if opt.HTML && opt.Command != "report" {
		return rt.writeUsage("--html is only valid with report", true)
	}
	if opt.Policy != "" && opt.Command != "check" {
		return rt.writeUsage("--policy is only valid with check", true)
	}
	if opt.All && opt.Command != "explain" {
		return rt.writeUsage("--all is only valid with explain", true)
	}
	if opt.Bundle != "" && opt.Command != "doctor" {
		return rt.writeUsage("--bundle is only valid with doctor", true)
	}
	rt.opt = opt
	rt.warnAllowShortSecret()
	rt.warnAllowShortSecret()
	switch opt.Command {
	case "version":
		return rt.cmdVersion(opt)
	case "doctor":
		return rt.cmdDoctor(opt)
	case "inspect":
		return rt.cmdInspect(opt)
	case "explain":
		return rt.cmdExplain(opt)
	case "diff":
		return rt.cmdDiff(opt)
	case "check":
		return rt.cmdCheck(opt)
	case "differential":
		return rt.cmdDifferential(opt)
	case "reproduce":
		return rt.cmdReproduce(opt)
	case "report":
		return rt.cmdReport(opt)
	default:
		if IsFutureCommand(opt.Command) {
			return rt.cmdUnsupported(opt)
		}
		return rt.writeUsage("unknown command "+redact.DiagnosticLabel(opt.Command), true)
	}
}

func (rt Runtime) cmdVersion(opt Options) int {
	if opt.JSON {
		return rt.writeJSON(newVersionReport(), nil)
	}
	return rt.emit([]byte(fmt.Sprintf("%s %s\n", version.Name, version.Version)), nil)
}

func (rt Runtime) cmdUnsupported(opt Options) int {
	msg := fmt.Sprintf("%s is not available in %s.", opt.Command, version.Version)
	if opt.Command == "report" {
		msg = fmt.Sprintf("report without --json or --html is not available in %s; use --json or --html.", version.Version)
	}
	if opt.JSON {
		rep := unsupportedReport{
			Schema:  "composelens.unsupported.v0",
			Command: opt.Command,
			State:   evidence.Unsupported,
			Message: msg,
		}
		code := rt.writeJSON(rep, nil)
		if code == exitcode.OK {
			return exitcode.Unsupported
		}
		return code
	}
	writeErr(rt.Stderr, "composelens: %s\n", msg)
	return exitcode.Unsupported
}

func (rt Runtime) fingerprinter() (*redact.Fingerprinter, error) {
	if rt.NewFingerprinter != nil {
		return rt.NewFingerprinter()
	}
	return redact.NewFingerprinter()
}

func (rt Runtime) failClosed(err error) int {
	writeErr(rt.Stderr, "composelens: refuse to write output: fail-closed (%v)\n", err)
	return exitcode.Safety
}

func (rt Runtime) resolveProject(opt Options) (string, error) {
	first := ""
	if len(opt.Files) > 0 {
		resolved, err := paths.Resolve(rt.Cwd, opt.Files[0])
		if err != nil {
			return "", err
		}
		first = resolved
	}
	return paths.ProjectDir(rt.Cwd, opt.ProjectDirectory, first)
}

func composeFileFromEnviron(environ []string) string {
	for _, kv := range environ {
		if strings.HasPrefix(kv, "COMPOSE_FILE=") {
			return strings.TrimPrefix(kv, "COMPOSE_FILE=")
		}
	}
	return ""
}

func (rt Runtime) loadProject(opt Options, budget ...*safety.Budget) (string, []discover.File, *safety.Budget, int, error) {
	b := safety.Optional(budget)
	if b == nil {
		b = safety.NewBudget()
	}
	project, err := rt.resolveProject(opt)
	if err != nil {
		return "", nil, b, exitcode.Input, sanitizeUserErr(opt, err)
	}
	if st, err := os.Stat(project); err != nil || !st.IsDir() {
		return "", nil, b, exitcode.Input, safety.NewParseError(safety.CodeProjectMissing, project, "project directory does not exist or is not a directory")
	}
	if err := rt.applyRedactConfig(opt, project, b); err != nil {
		return "", nil, b, exitcode.Input, sanitizeUserErr(opt, err)
	}
	files, err := discover.Discover(rt.Cwd, project, opt.Files, composeFileFromEnviron(rt.Environ), b)
	if err != nil {
		return "", nil, b, exitcode.Input, sanitizeUserErr(opt, err)
	}
	return project, files, b, exitcode.OK, nil
}

func (rt Runtime) loadInputs(opt Options, fp *redact.Fingerprinter, budget ...*safety.Budget) (string, []discover.File, []envsrc.Binding, *safety.Budget, int, error) {
	project, files, b, code, err := rt.loadProject(opt, budget...)
	if err != nil {
		return "", nil, nil, b, code, err
	}
	binds, err := envsrc.Collect(project, opt.EnvFiles, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		return "", nil, nil, b, exitcode.Input, sanitizeUserErr(opt, err)
	}
	return project, files, binds, b, exitcode.OK, nil
}

func (rt Runtime) applyRedactConfig(opt Options, project string, b *safety.Budget) error {
	path := strings.TrimSpace(opt.Redact)
	if path == "" {
		candidate := filepath.Join(project, redact.DiscoveredName)
		st, err := os.Stat(candidate)
		if err != nil || !st.Mode().IsRegular() {
			return nil
		}
		path = candidate
	}
	resolved, err := paths.Resolve(rt.Cwd, path)
	if err != nil {
		return &redact.Error{Kind: redact.KindMissingFile, Message: "redaction config is not readable"}
	}
	raw, err := safety.ReadCharged(b, resolved, safety.MaxFileBytes)
	if err != nil {
		if errors.Is(err, safety.ErrInputTooLarge) || safety.CodeOf(err) == safety.CodeFileTooLarge {
			return &redact.Error{Kind: redact.KindTooLarge, Message: "redaction config exceeds the byte bound"}
		}
		if safety.IsResourceBound(err) {
			return err
		}
		return &redact.Error{Kind: redact.KindMissingFile, Message: "redaction config is not readable"}
	}
	frags := redact.ConfigSecretFragments(raw)
	cfg, err := redact.Parse(raw)
	if err != nil {
		return redact.RedactInError(err, append(frags, path, resolved)...)
	}
	redact.Use(cfg)
	return nil
}

func sanitizeUserErr(opt Options, err error) error {
	vals := make([]string, 0, len(opt.Files)+len(opt.EnvFiles)+3)
	vals = append(vals, opt.Files...)
	vals = append(vals, opt.EnvFiles...)
	vals = append(vals, opt.LeftEnvFiles...)
	vals = append(vals, opt.RightEnvFiles...)
	vals = append(vals, opt.ProjectDirectory, opt.Command, opt.Redact, opt.Bundle)
	return redact.ScrubErrorTokens(redact.RedactInError(err, vals...))
}

func (rt Runtime) writeJSON(v any, secrets []string) int {
	raw, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		writeErr(rt.Stderr, "composelens: encode: %v\n", err)
		return exitcode.Internal
	}
	raw = append(raw, '\n')
	return rt.emit(raw, secrets)
}

func (rt Runtime) emit(raw []byte, secrets []string) int {
	if rt.opt.JSON {
		raw = rt.recordAllowShortSecret(raw)
	}
	if !rt.opt.JSON && !rt.opt.SARIF && !rt.opt.HTML {
		// Human text: C1, bidirectional and zero-width controls never belong to
		// ComposeLens's own text, so any left from data are shown escaped.
		raw = []byte(redact.EscapeInvisibles(string(raw)))
	}
	if code, ok := rt.guardOutput(raw, secrets); !ok {
		return code
	}
	if _, err := rt.Stdout.Write(raw); err != nil {
		writeErr(rt.Stderr, "composelens: write: %v\n", err)
		return exitcode.Internal
	}
	return exitcode.OK
}

func (rt Runtime) cmdDoctor(opt Options) int {
	if strings.TrimSpace(opt.Bundle) != "" {
		if opt.JSON {
			return rt.writeUsage("--json and --bundle are mutually exclusive", true)
		}
		return rt.writeSupportBundle(opt)
	}
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, _, code, err := rt.loadInputs(opt, fp)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	detect := rt.Detect
	if detect == nil {
		detect = engine.Detect
	}
	eng := detect()
	rep := buildDoctor(project, files, eng)
	secrets := append(envsrc.SecretValues(binds), fp.GuardMaterial()...)
	secrets = append(secrets, eng.GuardMaterial()...)
	if eng.Err != nil {
		return rt.fail(opt, exitcode.Input, eng.Err, secrets)
	}
	if opt.JSON {
		return rt.writeJSON(rep, secrets)
	}
	return rt.emit([]byte(formatDoctor(rep)), secrets)
}

func (rt Runtime) cmdInspect(opt Options) int {
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, b, code, err := rt.loadInputs(opt, fp)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	table, err := interp.Load(project, opt.EnvFiles, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, opt.EnvFiles...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	rep, in, err := buildInspect(project, files, binds, table, fp, opt.Profiles, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	rt.short = append(rt.short, shortSources(binds, &in)...)
	rt.rememberPublicRevisions(in)
	if path, ok := envsrc.UnappliedProjectEnv(project, opt.EnvFiles, rt.Cwd, rt.Environ); ok {
		rep.UnappliedSources = []UnappliedEnvSource{{
			Stage:     evidence.StageProject,
			Path:      path,
			Applied:   false,
			Certainty: evidence.Proven,
			Evidence:  evidence.Known,
		}}
	}
	secrets := inspectSecrets(binds, fp, in, opt.Profiles, rt.Environ)
	if opt.JSON {
		return rt.writeJSON(rep, secrets)
	}
	return rt.emit([]byte(formatInspect(rep)), secrets)
}

func (rt Runtime) writeUsage(msg string, includeUsage bool) int {
	ent, _ := diag.LookupID("cli.usage")
	body := diag.FormatHuman(msg, ent)
	if includeUsage {
		body += Usage()
	}
	writeErr(rt.Stderr, "%s", body)
	return exitcode.Usage
}

func (rt Runtime) fail(opt Options, code int, err error, secrets []string) int {
	err = sanitizeUserErr(opt, err)
	ent, _ := diag.Resolve(err, code)
	var raw []byte
	if opt.JSON {
		rep := errorReport{
			Schema:      "composelens.error.v0",
			State:       evidence.Known,
			Message:     err.Error(),
			Code:        ent.ID,
			Remediation: ent.Remediation,
			Doc:         ent.Doc,
		}
		encoded, encErr := json.MarshalIndent(rep, "", "  ")
		if encErr != nil {
			raw = []byte(diag.FormatHuman(err.Error(), ent))
		} else {
			raw = encoded
			raw = append(raw, '\n')
		}
	} else {
		raw = []byte(diag.FormatHuman(err.Error(), ent))
	}
	if gcode, ok := rt.guardOutput(raw, secrets); !ok {
		return gcode
	}
	writeErr(rt.Stderr, "%s", string(raw))
	return code
}

func platformInfo() PlatformInfo {
	shell, certainty := detectShell()
	return PlatformInfo{
		OS:        runtime.GOOS,
		Arch:      runtime.GOARCH,
		Compiler:  runtime.Compiler,
		NumCPU:    runtime.NumCPU(),
		Shell:     shell,
		Certainty: certainty,
	}
}

func detectShell() (string, string) {
	return detectShellUsing(runtime.GOOS, os.Getenv)
}

func detectShellUsing(goos string, getenv func(string) string) (string, string) {
	if goos == "windows" {
		if getenv("PSModulePath") != "" {
			if strings.Contains(strings.ToLower(getenv("PSModulePath")), "powershell\\7") || getenv("POWERSHELL_DISTRIBUTION_CHANNEL") != "" {
				return "pwsh", evidence.Inferred
			}
			return "powershell", evidence.Inferred
		}
		if getenv("ComSpec") != "" {
			return "cmd", evidence.Inferred
		}
		return "", evidence.Unknown
	}
	if sh := getenv("SHELL"); sh != "" {
		return filepath.Base(sh), evidence.Proven
	}
	return "", evidence.Unknown
}

func fileReports(files []discover.File) []FileReport {
	out := make([]FileReport, 0, len(files))
	for _, f := range files {
		out = append(out, FileReport{
			Path:      f.Path,
			Digest:    f.Digest,
			Origin:    f.Origin,
			Index:     f.Index,
			Evidence:  evidence.Known,
			Certainty: evidence.Proven,
		})
	}
	return out
}

func buildDoctor(project string, files []discover.File, eng engine.Info) doctorReport {
	fileEv := evidence.Known
	if len(files) == 0 {
		fileEv = evidence.Absent
	}
	return doctorReport{
		Schema:             "composelens.doctor.v0",
		Product:            version.Name,
		Version:            version.Version,
		Platform:           platformInfo(),
		Engine:             eng,
		EngineCapabilities: enginecap.FromDetect(eng.State, eng.Version),
		Inputs: InputsInfo{
			ProjectDirectory: project,
			Files:            fileReports(files),
			FileEvidence:     fileEv,
		},
		Features: FeatureInfo{
			Implemented: implementedFeatures,
			Deferred:    deferredFeatures,
		},
		Evidence: evidence.Known,
	}
}

func inspectSecrets(binds []envsrc.Binding, fp *redact.Fingerprinter, in explain.Input, flagProfiles []string, environ []string) []string {
	secrets := append(envsrc.SecretValues(binds), fp.GuardMaterial()...)
	secrets = append(secrets, interp.SecretFragments(in.Interp)...)
	secrets = append(secrets, merge.SecretFragments(in.Merge)...)
	active := profiles.Active(flagProfiles, environ)
	secrets = append(secrets, profiles.SecretFragments(active, in.Profiles)...)
	secrets = append(secrets, containerenv.SecretFragments(in.Container)...)
	secrets = append(secrets, normalize.SecretFragments(normalize.FromMerge(in.Merge))...)
	return secrets
}

func (rt Runtime) cmdExplain(opt Options) int {
	if opt.All && strings.TrimSpace(opt.Target) != "" {
		return rt.writeUsage("explain --all cannot be combined with a target", true)
	}
	if !opt.All && strings.TrimSpace(opt.Target) == "" {
		return rt.writeUsage("explain requires a target (service, services.name.field, or service:VAR)", true)
	}
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, b, code, err := rt.loadInputs(opt, fp)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	table, err := interp.Load(project, opt.EnvFiles, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, opt.EnvFiles...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	_, in, err := buildInspect(project, files, binds, table, fp, opt.Profiles, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	rt.short = append(rt.short, shortSources(binds, &in)...)
	rt.rememberPublicRevisions(in)
	if opt.All {
		g := provgraph.Assemble(provgraph.Input{Model: in, Env: binds})
		secrets := inspectSecrets(binds, fp, in, opt.Profiles, rt.Environ)
		secrets = append(secrets, provgraph.SecretFragments(g)...)
		if opt.JSON {
			return rt.writeJSON(provgraph.NewReport(g), secrets)
		}
		return rt.emit([]byte(provgraph.Human(g)), secrets)
	}
	result := explain.Account(opt.Target, in)
	secrets := inspectSecrets(binds, fp, in, opt.Profiles, rt.Environ)
	secrets = append(secrets, explain.SecretFragments(result)...)
	if opt.JSON {
		return rt.writeJSON(explainJSON(result), secrets)
	}
	return rt.emit([]byte(formatExplain(result)), secrets)
}

func diffSides(opt Options) (leftProfiles, rightProfiles, leftEnv, rightEnv []string) {
	leftProfiles = append([]string{}, opt.LeftProfiles...)
	if len(leftProfiles) == 0 {
		leftProfiles = append([]string{}, opt.Profiles...)
	}
	rightProfiles = append([]string{}, opt.RightProfiles...)
	if len(rightProfiles) == 0 {
		rightProfiles = append([]string{}, leftProfiles...)
	}
	leftEnv = append([]string{}, opt.LeftEnvFiles...)
	if len(leftEnv) == 0 {
		leftEnv = append([]string{}, opt.EnvFiles...)
	}
	rightEnv = append([]string{}, opt.RightEnvFiles...)
	if len(rightEnv) == 0 {
		rightEnv = append([]string{}, leftEnv...)
	}
	return leftProfiles, rightProfiles, leftEnv, rightEnv
}

func (rt Runtime) cmdDiff(opt Options) int {
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	leftP, rightP, leftEnv, rightEnv := diffSides(opt)
	project, files, b, code, err := rt.loadProject(opt)
	if err != nil {
		return rt.fail(opt, code, err, fp.GuardMaterial())
	}
	tableL, err := interp.Load(project, leftEnv, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, leftEnv...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, fp.GuardMaterial())
	}
	tableR, err := interp.Load(project, rightEnv, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, rightEnv...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, fp.GuardMaterial())
	}
	bindsL, err := envsrc.Collect(project, leftEnv, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, sanitizeUserErr(opt, err), fp.GuardMaterial())
	}
	bindsR, err := envsrc.Collect(project, rightEnv, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, sanitizeUserErr(opt, err), fp.GuardMaterial())
	}
	_, leftIn, err := buildInspect(project, files, bindsL, tableL, fp, leftP, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(bindsL), fp.GuardMaterial()...))
	}
	rt.short = append(rt.short, shortSources(bindsL, &leftIn)...)
	rt.rememberPublicRevisions(leftIn)
	_, rightIn, err := buildInspect(project, files, bindsR, tableR, fp, rightP, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(bindsR), fp.GuardMaterial()...))
	}
	rt.short = append(rt.short, shortSources(bindsR, &rightIn)...)
	rt.rememberPublicRevisions(rightIn)
	result := diff.Compare(leftIn, rightIn)
	secrets := inspectSecrets(bindsL, fp, leftIn, leftP, rt.Environ)
	secrets = append(secrets, inspectSecrets(bindsR, fp, rightIn, rightP, rt.Environ)...)
	secrets = append(secrets, diff.SecretFragments(result)...)
	if opt.JSON {
		return rt.writeJSON(diffJSON(leftP, rightP, leftEnv, rightEnv, result), secrets)
	}
	return rt.emit([]byte(formatDiff(leftP, rightP, leftEnv, rightEnv, result)), secrets)
}

func (rt Runtime) cmdCheck(opt Options) int {
	if opt.JSON && opt.SARIF {
		return rt.writeUsage("--json and --sarif are mutually exclusive", true)
	}
	if opt.JSON && opt.GitHub {
		return rt.writeUsage("--json and --github are mutually exclusive", true)
	}
	if opt.SARIF && opt.GitHub {
		return rt.writeUsage("--sarif and --github are mutually exclusive", true)
	}
	var pol *policy.Document
	var policySecrets []string
	b := safety.NewBudget()
	if strings.TrimSpace(opt.Policy) != "" {
		resolved, err := paths.Resolve(rt.Cwd, opt.Policy)
		if err != nil {
			return rt.fail(opt, exitcode.Input, &policy.Error{Kind: policy.KindMissingFile, Message: "policy file is not readable"}, nil)
		}
		doc, raw, err := policy.Load(resolved, b)
		policySecrets = policy.SecretFragments(raw)
		if err != nil {
			err = redact.RedactInError(err, policySecrets...)
			return rt.fail(opt, exitcode.Input, err, policySecrets)
		}
		pol = doc
	}
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, b, code, err := rt.loadInputs(opt, fp, b)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(append(envsrc.SecretValues(binds), fp.GuardMaterial()...), policySecrets...))
	}
	if len(files) == 0 {
		err := safety.NewParseError(safety.CodeNoComposeFile, project, "no Compose file found (compose.yaml, compose.yml, docker-compose.yaml, docker-compose.yml)")
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	table, err := interp.Load(project, opt.EnvFiles, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, opt.EnvFiles...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, append(append(envsrc.SecretValues(binds), fp.GuardMaterial()...), policySecrets...))
	}
	_, in, err := buildInspect(project, files, binds, table, fp, opt.Profiles, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(append(envsrc.SecretValues(binds), fp.GuardMaterial()...), policySecrets...))
	}
	rt.short = append(rt.short, shortSources(binds, &in)...)
	rt.rememberPublicRevisions(in)
	result := check.Evaluate(in).WithLocationBase(project)
	result = check.ApplyPolicy(result, pol)
	secrets := inspectSecrets(binds, fp, in, opt.Profiles, rt.Environ)
	secrets = append(secrets, check.SecretFragments(result)...)
	secrets = append(secrets, policySecrets...)
	if opt.SARIF {
		raw, err := check.SARIF(result)
		if err != nil {
			writeErr(rt.Stderr, "composelens: encode: %v\n", err)
			return exitcode.Internal
		}
		raw = append(raw, '\n')
		return rt.finishCheck(raw, secrets, result)
	}
	if opt.GitHub {
		bundle, err := ci.FromResult(result, ci.LinksFromEnv())
		if err != nil {
			writeErr(rt.Stderr, "composelens: encode: %v\n", err)
			return exitcode.Internal
		}
		if code := rt.writeGitHubArtifacts(bundle, secrets); code != exitcode.OK {
			return code
		}
		code := rt.finishCheck(bundle.Log, secrets, result)
		return ci.MapActionExit(code, result, os.Getenv(ci.EnvFailOn))
	}
	if opt.JSON {
		raw, err := check.JSON(result)
		if err != nil {
			writeErr(rt.Stderr, "composelens: encode: %v\n", err)
			return exitcode.Internal
		}
		raw = append(raw, '\n')
		return rt.finishCheck(raw, secrets, result)
	}
	return rt.finishCheck([]byte(check.Human(result)), secrets, result)
}

func (rt Runtime) finishCheck(raw []byte, secrets []string, result check.Result) int {
	code := rt.emit(raw, secrets)
	if code != exitcode.OK {
		return code
	}
	return check.AssertionExit(result)
}

func (rt Runtime) writeGitHubArtifacts(bundle ci.Bundle, secrets []string) int {
	jsonPath := strings.TrimSpace(os.Getenv(ci.EnvJSONPath))
	sarifPath := strings.TrimSpace(os.Getenv(ci.EnvSARIFPath))
	summaryPath := strings.TrimSpace(os.Getenv(ci.EnvSummaryPath))
	stepPath := strings.TrimSpace(os.Getenv(ci.EnvStepSummary))
	if jsonPath != "" {
		if code := rt.writeGuardedFile(jsonPath, appendNewline(bundle.JSON), secrets, false); code != exitcode.OK {
			return code
		}
	}
	if sarifPath != "" {
		if code := rt.writeGuardedFile(sarifPath, appendNewline(bundle.SARIF), secrets, false); code != exitcode.OK {
			return code
		}
	}
	sum := []byte(bundle.Summary)
	if summaryPath != "" {
		if code := rt.writeGuardedFile(summaryPath, sum, secrets, false); code != exitcode.OK {
			return code
		}
	}
	if stepPath != "" && !sameFSPath(summaryPath, stepPath) {
		if code := rt.writeGuardedFile(stepPath, sum, secrets, true); code != exitcode.OK {
			return code
		}
	}
	return exitcode.OK
}

func appendNewline(raw []byte) []byte {
	if len(raw) == 0 || raw[len(raw)-1] == '\n' {
		return raw
	}
	out := make([]byte, len(raw)+1)
	copy(out, raw)
	out[len(raw)] = '\n'
	return out
}

func sameFSPath(a, b string) bool {
	a = strings.TrimSpace(a)
	b = strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	a = filepath.Clean(a)
	b = filepath.Clean(b)
	if strings.EqualFold(a, b) {
		return true
	}
	aa, err1 := filepath.Abs(a)
	bb, err2 := filepath.Abs(b)
	if err1 != nil || err2 != nil {
		return false
	}
	return strings.EqualFold(aa, bb)
}

func (rt Runtime) writeGuardedFile(path string, raw []byte, secrets []string, appendTo bool) int {
	if code, ok := rt.guardOutput(raw, secrets); !ok {
		return code
	}
	// Artifact paths come from the environment and are replaced on every run,
	// but never through a symbolic link.
	if st, err := os.Lstat(path); err == nil && st.Mode()&os.ModeSymlink != 0 {
		writeErr(rt.Stderr, "composelens: write: refusing to write through a symbolic link (%s)\n", safety.CodeOutputExists)
		return exitcode.Input
	}
	flag := os.O_WRONLY | os.O_CREATE | os.O_TRUNC | openNoFollow
	if appendTo {
		flag = os.O_WRONLY | os.O_CREATE | os.O_APPEND | openNoFollow
	}
	f, err := os.OpenFile(path, flag, 0o644)
	if err != nil {
		writeErr(rt.Stderr, "composelens: write: %v\n", err)
		return exitcode.Internal
	}
	_, werr := f.Write(raw)
	cerr := f.Close()
	if werr != nil {
		writeErr(rt.Stderr, "composelens: write: %v\n", werr)
		return exitcode.Internal
	}
	if cerr != nil {
		writeErr(rt.Stderr, "composelens: write: %v\n", cerr)
		return exitcode.Internal
	}
	return exitcode.OK
}

func (rt Runtime) cmdDifferential(opt Options) int {
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, b, code, err := rt.loadInputs(opt, fp)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	table, err := interp.Load(project, opt.EnvFiles, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, opt.EnvFiles...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	insp, in, err := buildInspect(project, files, binds, table, fp, opt.Profiles, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	rt.short = append(rt.short, shortSources(binds, &in)...)
	rt.rememberPublicRevisions(in)
	paths := make([]string, 0, len(files))
	for _, f := range files {
		paths = append(paths, f.Path)
	}
	cap := rt.engineCapture(opt, engineadapter.Request{
		ProjectDir: project,
		Files:      paths,
		EnvFiles:   envsrc.ReplacementEnvFiles(opt.EnvFiles, rt.Environ),
		Profiles:   opt.Profiles,
	}, insp.Includes, b)
	if cap.Err != nil && safety.IsResourceBound(cap.Err) {
		return rt.fail(opt, exitcode.Input, cap.Err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	var eng explain.Input
	if cap.State == engineadapter.StateCaptured && cap.ConfigStdout != "" {
		eng, err = differential.ParseConfig(cap.ConfigStdout)
		if err != nil {
			return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
		}
	}
	rep := differential.CompareInputs(in, eng, differential.Meta{
		EngineState: cap.State,
		SkipReason:  skipReason(cap),
		Version:     cap.Version,
		Command:     cap.ConfigCommand,
		Project:     project,
	})
	secrets := inspectSecrets(binds, fp, in, opt.Profiles, rt.Environ)
	secrets = append(secrets, differential.SecretFragments(rep)...)
	if opt.JSON {
		return rt.writeJSON(rep, secrets)
	}
	return rt.emit([]byte(differential.Human(rep)), secrets)
}

func (rt Runtime) cmdReproduce(opt Options) int {
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, _, code, err := rt.loadInputs(opt, fp)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	filePaths := make([]string, 0, len(files))
	for _, f := range files {
		filePaths = append(filePaths, f.Path)
	}
	envFiles := make([]string, 0)
	for _, f := range envsrc.ReplacementEnvFiles(opt.EnvFiles, rt.Environ) {
		resolved, err := paths.Resolve(rt.Cwd, f)
		if err != nil {
			return rt.fail(opt, exitcode.Input, sanitizeUserErr(opt, err), append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
		}
		envFiles = append(envFiles, resolved)
	}
	var profileNames []string
	for _, a := range profiles.Active(opt.Profiles, rt.Environ) {
		if a.Secret {
			writeErr(rt.Stderr, "composelens: refuse to write output: fail-closed (secret-shaped profile cannot be inlined)\n")
			return exitcode.Safety
		}
		profileNames = append(profileNames, a.Name)
	}
	cmd := reproduction.Generate(reproduction.Input{
		ProjectDir: project,
		Files:      filePaths,
		EnvFiles:   envFiles,
		Profiles:   profileNames,
	})
	secrets := append(envsrc.SecretValues(binds), fp.GuardMaterial()...)
	if err := reproduction.RejectSecrets(cmd, secrets); err != nil {
		writeErr(rt.Stderr, "composelens: refuse to write output: fail-closed (%s)\n", err.Error())
		return exitcode.Safety
	}
	rep := reproduceReport{
		Schema:           reproduction.Schema,
		Product:          version.Name,
		Version:          version.Version,
		Disclaimer:       "exact docker compose config invocation that recreates the modeled configuration — files and flags only; not an engine differential",
		Argv:             cmd.Argv,
		Command:          cmd.Line,
		ProjectDirectory: project,
		Files:            filePaths,
		EnvFiles:         envFiles,
		Profiles:         profileNames,
		Evidence:         evidence.Known,
		Certainty:        evidence.Proven,
	}
	if opt.JSON {
		return rt.writeJSON(rep, secrets)
	}
	return rt.emit([]byte(formatReproduce(rep)), secrets)
}

func (rt Runtime) cmdReport(opt Options) int {
	if opt.JSON && opt.HTML {
		return rt.writeUsage("--json and --html are mutually exclusive", true)
	}
	if !opt.JSON && !opt.HTML {
		return rt.cmdUnsupported(opt)
	}
	fp, err := rt.fingerprinter()
	if err != nil {
		return rt.failClosed(err)
	}
	project, files, binds, b, code, err := rt.loadInputs(opt, fp)
	rt.short = shortSources(binds, nil)
	if err != nil {
		return rt.fail(opt, code, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	table, err := interp.Load(project, opt.EnvFiles, rt.Cwd, rt.Environ, fp, b)
	if err != nil {
		err = redact.RedactInError(err, append(append([]string{}, opt.EnvFiles...), envsrc.ComposeEnvFileList(rt.Environ)...)...)
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	inspectRep, in, err := buildInspect(project, files, binds, table, fp, opt.Profiles, rt.Environ, b)
	if err != nil {
		return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	rt.short = append(rt.short, shortSources(binds, &in)...)
	rt.rememberPublicRevisions(in)
	g := provgraph.Assemble(provgraph.Input{Model: in, Env: binds})
	checkResult := check.Evaluate(in)
	diffResult := diff.Compare(in, in)
	filePaths := make([]string, 0, len(files))
	for _, f := range files {
		filePaths = append(filePaths, f.Path)
	}
	cap := rt.engineCapture(opt, engineadapter.Request{
		ProjectDir: project,
		Files:      filePaths,
		EnvFiles:   envsrc.ReplacementEnvFiles(opt.EnvFiles, rt.Environ),
		Profiles:   opt.Profiles,
	}, inspectRep.Includes, b)
	if cap.Err != nil && safety.IsResourceBound(cap.Err) {
		return rt.fail(opt, exitcode.Input, cap.Err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
	}
	var eng explain.Input
	if cap.State == engineadapter.StateCaptured && cap.ConfigStdout != "" {
		eng, err = differential.ParseConfig(cap.ConfigStdout)
		if err != nil {
			return rt.fail(opt, exitcode.Input, err, append(envsrc.SecretValues(binds), fp.GuardMaterial()...))
		}
	}
	diffRep := differential.CompareInputs(in, eng, differential.Meta{
		EngineState: cap.State,
		SkipReason:  skipReason(cap),
		Version:     cap.Version,
		Command:     cap.ConfigCommand,
		Project:     project,
	})
	srcFiles := make([]report.File, 0, len(inspectRep.Files))
	for _, f := range inspectRep.Files {
		srcFiles = append(srcFiles, report.File{
			Path: f.Path, Digest: f.Digest, Origin: f.Origin, Index: f.Index,
			Evidence: f.Evidence, Certainty: f.Certainty,
		})
	}
	srcServices := make([]report.Service, 0, len(inspectRep.Services))
	for _, s := range inspectRep.Services {
		srcServices = append(srcServices, report.Service{
			Name: s.Name, Identity: idpath.Join(s.Name, ""), Location: s.Location,
			Evidence: s.Evidence, Certainty: s.Certainty,
		})
	}
	pkg := report.Assemble(report.Input{
		Project:      project,
		Files:        srcFiles,
		Services:     srcServices,
		Graph:        g,
		Check:        checkResult,
		Diff:         diffResult,
		Differential: diffRep,
		FindingNodes: findingNodes(g, checkResult),
	})
	raw, err := report.Encode(pkg)
	if err != nil {
		writeErr(rt.Stderr, "composelens: encode: %v\n", err)
		return exitcode.Internal
	}
	raw = rt.recordAllowShortSecret(raw)
	if err := report.ValidateBytes(raw); err != nil {
		writeErr(rt.Stderr, "composelens: report schema: %v\n", err)
		return exitcode.Internal
	}
	secrets := inspectSecrets(binds, fp, in, opt.Profiles, rt.Environ)
	secrets = append(secrets, provgraph.SecretFragments(g)...)
	secrets = append(secrets, check.SecretFragments(checkResult)...)
	secrets = append(secrets, diff.SecretFragments(diffResult)...)
	secrets = append(secrets, differential.SecretFragments(diffRep)...)
	if opt.HTML {
		page, err := report.HTML(raw)
		if err != nil {
			if safety.IsResourceBound(err) {
				return rt.fail(opt, exitcode.Input, err, secrets)
			}
			writeErr(rt.Stderr, "composelens: report html: %v\n", err)
			return exitcode.Internal
		}
		return rt.emit(page, secrets)
	}
	return rt.emit(raw, secrets)
}

func formatReproduce(r reproduceReport) string {
	var b bytes.Buffer
	writeText(&b, "ComposeLens reproduce — %s\n", r.Disclaimer)
	writeText(&b, "%s\n", r.Command)
	return b.String()
}

func buildInspect(project string, files []discover.File, binds []envsrc.Binding, table *interp.Table, fp *redact.Fingerprinter, flagProfiles []string, environ []string, b *safety.Budget) (inspectReport, explain.Input, error) {
	var services []ServiceReport
	var items []interp.Value
	var overlay []*composeparse.Document
	graphs := make([]IncludeGraphReport, 0)
	chains := map[string][]string{}
	seenInterp := map[string]bool{}
	var includeGraphs []*include.Graph
	var getter interp.Getter
	if table != nil {
		getter = table
	}
	for _, f := range files {
		first, err := composeparse.Parse(f)
		if err != nil {
			return inspectReport{}, explain.Input{}, err
		}
		// Every YAML document of a file, in order (Compose merges them).
		for _, doc := range append([]*composeparse.Document{first}, first.More...) {
			for _, s := range doc.Services {
				services = append(services, ServiceReport{
					Name:      s.Name,
					Location:  s.Location,
					Evidence:  evidence.Known,
					Certainty: evidence.Proven,
				})
			}
			items = append(items, interp.ResolveScalars(composeparse.StringScalars(doc), table, fp)...)
			seenInterp[doc.File.Path] = true
			expanded := include.Expand(doc, include.LoaderWithBudget(b), getter)
			if expanded.Err != nil {
				return inspectReport{}, explain.Input{}, expanded.Err
			}
			overlay = append(overlay, expanded.Docs...)
			if expanded.Graph != nil {
				graphs = append(graphs, includeGraphReport(expanded.Graph))
				includeGraphs = append(includeGraphs, expanded.Graph)
			}
			for k, v := range expanded.Chains {
				if _, ok := chains[k]; !ok {
					chains[k] = v
				}
			}
			for _, d := range expanded.Docs {
				if d == nil {
					continue
				}
				if !seenInterp[d.File.Path] {
					seenInterp[d.File.Path] = true
					items = append(items, interp.ResolveScalars(composeparse.StringScalars(d), table, fp)...)
				}
				if d.File.Path == doc.File.Path {
					continue
				}
				for _, s := range d.Services {
					services = append(services, ServiceReport{
						Name:      s.Name,
						Location:  s.Location,
						Evidence:  evidence.Known,
						Certainty: evidence.Proven,
					})
				}
			}
		}
	}
	extGraphs := make([]ExtendsGraphReport, 0)
	extOrigins := map[string]extends.Field{}
	var extEngine []*extends.Graph
	resolved := make([]*composeparse.Document, 0, len(overlay))
	for _, d := range overlay {
		er := extends.Apply(d, extends.LoaderWithBudget(b), getter)
		if er.Err != nil {
			return inspectReport{}, explain.Input{}, er.Err
		}
		if er.Doc != nil {
			resolved = append(resolved, er.Doc)
		}
		if er.Graph != nil && (er.Graph.HasCycle || len(er.Graph.Refs) > 0) {
			extGraphs = append(extGraphs, extendsGraphReport(er.Graph))
			extEngine = append(extEngine, er.Graph)
		}
		for _, f := range er.Fields {
			extOrigins[f.Path] = f
		}
	}
	merged := merge.Documents(resolved, table)
	active := profiles.Active(flagProfiles, environ)
	activated := profiles.Activate(merged, active)
	cen, err := containerenv.ResolveConfined(project, merged, envsrc.HostMap(environ), getter, b)
	if err != nil {
		return inspectReport{}, explain.Input{}, err
	}
	fileEv := evidence.Known
	if len(files) == 0 {
		fileEv = evidence.Absent
	}
	rep := inspectReport{
		Schema:                         "composelens.inspect.v0",
		Product:                        version.Name,
		Version:                        version.Version,
		View:                           "source-level",
		Disclaimer:                     "source-level view — not resolved provenance",
		ProjectDirectory:               project,
		Files:                          fileReports(files),
		FileEvidence:                   fileEv,
		Services:                       services,
		Environment:                    groupEnv(envsrc.MarkSecretKeys(binds, interp.SecretVariableKeys(items))),
		InterpolationDisclaimer:        "interpolation stage only — per-file (including files pulled in by include:), before merge; not container environment; nested defaults expand as in Compose",
		Interpolation:                  interpReports(items),
		IncludesDisclaimer:             "top-level include: after per-file interpolation, before merge; included files are the base, including file overrides; long-form env_file and project_directory are not applied (unknown vs official engine)",
		Includes:                       graphs,
		ExtendsDisclaimer:              "service extends after interpolation (and include expansion of each file), before merge; mapping form {service, file?}; relationship keys are not inherited; string short form is unsupported; not container-environment precedence",
		Extends:                        extGraphs,
		MergeDisclaimer:                "multi-file merge after interpolation, include expansion, and extends — scalars override, maps deep-merge, sequences append (unique-key dedup for ports/volumes/secrets/configs; command/entrypoint/healthcheck.test replace), !reset/!override; not container-environment precedence",
		Merge:                          mergeReports(merged, chains, extOrigins),
		ProfilesDisclaimer:             "profile activation after merge — no-profiles always on; enable if any listed profile is active; a profiled depends_on target with no active profile is not auto-enabled (certainty unknown)",
		ActiveProfiles:                 activeProfileReports(active),
		ProfileServices:                profileServiceReports(activated),
		ContainerEnvironmentDisclaimer: "container environment after interpolation, include, extends, merge, and profiles — env_file then environment (environment wins); later env_file overrides earlier; list-form KEY with no value is host-shell pass-through; Dockerfile ENV and run -e are not applied",
		ContainerEnvironment:           containerEnvReports(cen),
		NormalizationDisclaimer:        "canonical dual-form fields after merge — short/long ports, volumes, labels, command/entrypoint representation, healthcheck.test; not a new resolver; shell vs exec stay distinct; environment/env_file stay with container environment",
		Normalization:                  normalizationReports(normalize.FromMerge(merged)),
		Evidence:                       evidence.Unresolved,
	}
	in := explain.Input{
		Interp:        items,
		Merge:         merged,
		Chains:        chains,
		Extends:       extOrigins,
		Profiles:      activated,
		Container:     cen,
		IncludeGraphs: includeGraphs,
		ExtendsGraphs: extEngine,
	}
	return rep, in, nil
}

func includeGraphReport(g *include.Graph) IncludeGraphReport {
	rep := IncludeGraphReport{}
	if g == nil {
		return rep
	}
	rep.File = g.File
	rep.HasCycle = g.HasCycle
	rep.Refs = make([]IncludeRefReport, 0, len(g.Refs))
	for _, ref := range g.Refs {
		item := IncludeRefReport{
			Form:              ref.Spec.Form,
			Path:              ref.Spec.Path,
			Resolved:          ref.Resolved,
			State:             ref.State,
			Reason:            ref.Reason,
			Certainty:         ref.Certainty,
			Evidence:          ref.Evidence,
			UnsupportedFields: ref.Spec.UnsupportedFields,
			CycleVia:          ref.CycleVia,
		}
		if ref.Nested != nil {
			nested := includeGraphReport(ref.Nested)
			item.Nested = &nested
		}
		rep.Refs = append(rep.Refs, item)
	}
	return rep
}

func extendsGraphReport(g *extends.Graph) ExtendsGraphReport {
	rep := ExtendsGraphReport{}
	if g == nil {
		return rep
	}
	rep.File = g.File
	rep.HasCycle = g.HasCycle
	rep.Refs = make([]ExtendsRefReport, 0, len(g.Refs))
	for _, ref := range g.Refs {
		rep.Refs = append(rep.Refs, extendsRefReport(ref))
	}
	return rep
}

func extendsRefReport(ref extends.Ref) ExtendsRefReport {
	item := ExtendsRefReport{
		Name:        ref.Name,
		Form:        ref.Form,
		Service:     ref.Service,
		File:        ref.File,
		Resolved:    ref.Resolved,
		State:       ref.State,
		Reason:      ref.Reason,
		Certainty:   ref.Certainty,
		Evidence:    ref.Evidence,
		Excluded:    ref.Excluded,
		CycleVia:    ref.CycleVia,
		BaseFile:    ref.BaseFile,
		BaseService: ref.BaseService,
	}
	if ref.Nested != nil {
		nested := extendsRefReport(*ref.Nested)
		item.Nested = &nested
	}
	return item
}

func activeProfileReports(active []profiles.ActiveProfile) []ActiveProfileReport {
	out := make([]ActiveProfileReport, 0, len(active))
	for _, a := range active {
		name := a.Name
		if a.Secret {
			name = "[redacted]"
		}
		out = append(out, ActiveProfileReport{
			Name:      name,
			Source:    a.Source,
			Redacted:  a.Secret,
			Evidence:  a.Evidence,
			Certainty: a.Certainty,
		})
	}
	return out
}

func profileServiceReports(svcs []profiles.Service) []ProfileServiceReport {
	out := make([]ProfileServiceReport, 0, len(svcs))
	for _, s := range svcs {
		listed := make([]string, 0, len(s.Listed))
		reason := s.Reason
		for _, p := range s.Listed {
			if redact.LooksLikeSecret(p) {
				listed = append(listed, "[redacted]")
				reason = strings.ReplaceAll(reason, p, "[redacted]")
			} else {
				listed = append(listed, p)
			}
		}
		if redact.LooksLikeSecret(s.Matched) {
			reason = strings.ReplaceAll(reason, s.Matched, "[redacted]")
		}
		rep := ProfileServiceReport{
			Name:      s.Name,
			State:     s.State,
			Reason:    reason,
			Listed:    listed,
			Certainty: s.Certainty,
			Evidence:  s.Evidence,
		}
		if s.Matched != "" {
			m := s.Matched
			if redact.LooksLikeSecret(m) {
				m = "[redacted]"
			}
			rep.Matched = &m
		}
		if s.MatchedSource != "" {
			src := s.MatchedSource
			rep.MatchedSource = &src
		}
		if s.ImplicitOf != "" {
			imp := s.ImplicitOf
			rep.ImplicitOf = &imp
		}
		out = append(out, rep)
	}
	return out
}

func containerEnvReports(svcs []containerenv.ServiceEnv) []ContainerEnvServiceReport {
	out := make([]ContainerEnvServiceReport, 0, len(svcs))
	for _, se := range svcs {
		rep := ContainerEnvServiceReport{
			Service:   se.Service,
			Files:     make([]ContainerEnvFileReport, 0, len(se.Files)),
			Variables: make([]ContainerEnvVarReport, 0, len(se.Vars)),
		}
		for _, f := range se.Files {
			rep.Files = append(rep.Files, ContainerEnvFileReport{
				Path:      f.Path,
				Resolved:  f.Resolved,
				State:     f.State,
				Required:  f.Required,
				Format:    f.Format,
				Reason:    f.Reason,
				Certainty: f.Certainty,
				Evidence:  f.Evidence,
			})
		}
		for _, v := range se.Vars {
			item := ContainerEnvVarReport{
				Key:        v.Key,
				State:      v.State,
				Winner:     containerEnvSource(v.Winner, v.Secret),
				Value:      ValueView{State: v.State, Redacted: v.Secret},
				Overridden: make([]ContainerEnvSourceReport, 0, len(v.Overridden)),
				Reason:     v.Reason,
				Certainty:  v.Certainty,
				Evidence:   v.Evidence,
			}
			if !v.Secret && v.State == containerenv.StateSet {
				t := v.Value
				item.Value.Text = &t
			}
			for _, o := range v.Overridden {
				item.Overridden = append(item.Overridden, containerEnvSource(o, v.Secret))
			}
			rep.Variables = append(rep.Variables, item)
		}
		out = append(out, rep)
	}
	return out
}

func containerEnvSource(c containerenv.Contributor, secret bool) ContainerEnvSourceReport {
	rep := ContainerEnvSourceReport{
		Kind:  c.Kind,
		Path:  c.Path,
		Line:  c.Line,
		Form:  c.Form,
		Value: ValueView{State: "source", Redacted: secret},
	}
	if !secret && !c.Unset {
		t := c.Value
		rep.Value.Text = &t
	}
	return rep
}

func mergeReports(fields []merge.Field, chains map[string][]string, origins map[string]extends.Field) []MergeFieldReport {
	out := make([]MergeFieldReport, 0, len(fields))
	for _, f := range fields {
		rep := MergeFieldReport{
			Path:       f.Path,
			Action:     f.Action,
			Winner:     f.Winner,
			Line:       f.Line,
			Value:      ValueView{State: f.Action, Redacted: f.Secret},
			Overridden: []MergeContributor{},
			Certainty:  f.Certainty,
			Evidence:   f.Evidence,
		}
		if chains != nil {
			if ch := chains[f.Winner]; len(ch) > 1 {
				rep.IncludeChain = ch
			}
		}
		if origins != nil {
			if o, ok := origins[f.Path]; ok && o.Origin != "" {
				rep.ExtendsOrigin = o.Origin
				if len(o.Chain) > 1 {
					rep.ExtendsChain = o.Chain
				}
				rep.ExtendsBaseFile = o.BaseFile
				rep.ExtendsBaseService = o.BaseService
			}
		}
		if !f.Secret {
			t := f.Value
			rep.Value.Text = &t
		}
		for _, c := range f.Overridden {
			cr := MergeContributor{File: c.File, Line: c.Line, Action: c.Action, Value: ValueView{State: c.Action, Redacted: f.Secret}}
			if !f.Secret {
				v := c.Value
				cr.Value.Text = &v
			}
			rep.Overridden = append(rep.Overridden, cr)
		}
		out = append(out, rep)
	}
	return out
}

func normalizationReports(m normalize.Model) []NormalizationServiceReport {
	out := make([]NormalizationServiceReport, 0, len(m.Services))
	for _, s := range m.Services {
		rep := NormalizationServiceReport{
			Service: s.Name,
			Ports:   make([]NormalizationItemReport, 0, len(s.Ports)),
			Volumes: make([]NormalizationItemReport, 0, len(s.Volumes)),
			Labels:  make([]NormalizationItemReport, 0, len(s.Labels.Pairs)),
		}
		for _, p := range s.Ports {
			rep.Ports = append(rep.Ports, normalizationItem("", "", "", normalize.DisplayPort(p), p.Provenance))
		}
		for _, v := range s.Volumes {
			rep.Volumes = append(rep.Volumes, normalizationItem("", "", "", normalize.DisplayVolume(v), v.Provenance))
		}
		for _, l := range s.Labels.Pairs {
			rep.Labels = append(rep.Labels, normalizationItem(l.Key, "", "", l.Key+"="+l.Value, l.Provenance))
		}
		if s.Command != nil {
			item := normalizationItem("", s.Command.Form, "", normalize.DisplayCommand(s.Command), s.Command.Provenance)
			rep.Command = &item
		}
		if s.Entrypoint != nil {
			item := normalizationItem("", s.Entrypoint.Form, "", normalize.DisplayCommand(s.Entrypoint), s.Entrypoint.Provenance)
			rep.Entrypoint = &item
		}
		if s.Healthcheck != nil {
			item := normalizationItem("", "", s.Healthcheck.Kind, normalize.DisplayHealthcheck(s.Healthcheck), s.Healthcheck.Provenance)
			rep.Healthcheck = &item
		}
		out = append(out, rep)
	}
	return out
}

func normalizationItem(key, form, kind, canonical string, p normalize.Provenance) NormalizationItemReport {
	rep := NormalizationItemReport{
		Key:       key,
		Form:      form,
		Kind:      kind,
		Source:    p.Source,
		Line:      p.Line,
		Value:     ValueView{State: "canonical", Redacted: p.Secret},
		Certainty: p.Certainty,
		Evidence:  p.Evidence,
		Reason:    p.Reason,
	}
	if !p.Secret {
		rep.Canonical = canonical
		t := canonical
		rep.Value.Text = &t
	}
	return rep
}

func interpReports(items []interp.Value) []InterpValueReport {
	out := make([]InterpValueReport, 0, len(items))
	for _, v := range items {
		rep := InterpValueReport{
			Path:        v.Path,
			Location:    v.Location,
			Raw:         v.Raw,
			Form:        v.Form,
			State:       v.State,
			Variables:   v.Variables,
			Value:       ValueView{State: v.State, Redacted: v.Secret},
			Fingerprint: redact.DisplayForSecret(v.Fingerprint, v.Secret),
			Certainty:   v.Certainty,
			Evidence:    v.Evidence,
		}
		if v.Secret && !redact.RawReferenceShowable(v.Path, v.Raw) {
			rep.Raw = "[redacted]"
		}
		if !v.Secret {
			t := v.Resolved
			rep.Value.Text = &t
		}
		if v.Error != "" {
			msg := v.Error
			if v.Secret {
				msg = "[redacted]"
			}
			rep.Error = &msg
		}
		if v.Source != nil {
			src := interpSourceReport{Key: v.Source.Key, Stage: v.Source.Stage}
			if v.Source.Path != "" {
				p := v.Source.Path
				src.Path = &p
			}
			if v.Source.Line > 0 {
				ln := v.Source.Line
				src.Line = &ln
			}
			rep.Source = &src
		}
		out = append(out, rep)
	}
	return out
}

func groupEnv(binds []envsrc.Binding) []EnvKeyReport {
	idx := map[string][]envsrc.Binding{}
	for _, b := range binds {
		idx[b.Key] = append(idx[b.Key], b)
	}
	keys := make([]string, 0, len(idx))
	for k := range idx {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]EnvKeyReport, 0, len(keys))
	for _, k := range keys {
		group := idx[k]
		secret := false
		sources := make([]EnvSourceReport, 0, len(group))
		for _, b := range group {
			if b.Secret {
				secret = true
			}
			var pathPtr *string
			var linePtr *int
			if b.Path != "" {
				p := b.Path
				pathPtr = &p
			}
			if b.Line > 0 {
				ln := b.Line
				linePtr = &ln
			}
			val := ValueView{State: evidence.Known, Redacted: b.Secret}
			if !b.Secret {
				t := b.RawValue
				val.Text = &t
			}
			sources = append(sources, EnvSourceReport{
				Reason:      b.Reason,
				Stage:       b.Stage,
				Path:        pathPtr,
				Line:        linePtr,
				Fingerprint: redact.DisplayForSecret(b.Fingerprint, b.Secret),
				Value:       val,
				Certainty:   b.Certainty,
			})
		}
		out = append(out, EnvKeyReport{
			Key:      k,
			Secret:   secret,
			Evidence: evidence.Unresolved,
			Sources:  sources,
		})
	}
	return out
}

func formatDoctor(r doctorReport) string {
	var b bytes.Buffer
	writeText(&b, "ComposeLens doctor (%s)\n\n", r.Version)
	writeText(&b, "Platform: %s/%s  shell: %s (%s)\n", r.Platform.OS, r.Platform.Arch, dash(r.Platform.Shell), r.Platform.Certainty)
	eng := r.Engine
	switch eng.State {
	case evidence.Known:
		writeText(&b, "Engine: %s %s (detection only; no render)\n", eng.Kind, eng.Version)
	case evidence.Absent:
		writeText(&b, "Engine: absent (%s)\n", eng.Detail)
	default:
		writeText(&b, "Engine: unknown (%s)\n", dash(eng.Detail))
	}
	writeText(&b, "Engine support: %s (%s)\n", dash(r.EngineCapabilities.Support), dash(r.EngineCapabilities.Detail))
	writeText(&b, "Project directory: %s\n", r.Inputs.ProjectDirectory)
	writeText(&b, "Files (%s): %d\n", r.Inputs.FileEvidence, len(r.Inputs.Files))
	for _, f := range r.Inputs.Files {
		writeText(&b, "  %d  %s  %s  origin=%s\n", f.Index, f.Path, f.Digest, f.Origin)
	}
	writeText(&b, "\n%s implements: %s\n", version.Version, strings.Join(r.Features.Implemented, ", "))
	writeText(&b, "%s does not: %s\n", version.Version, strings.Join(r.Features.Deferred, ", "))
	return b.String()
}

func formatInspect(r inspectReport) string {
	var b bytes.Buffer
	writeText(&b, "ComposeLens inspect — %s\n\n", r.Disclaimer)
	writeText(&b, "Project directory: %s\n", r.ProjectDirectory)
	writeText(&b, "Files (%s): %d\n", r.FileEvidence, len(r.Files))
	for _, f := range r.Files {
		writeText(&b, "  %d  %s  %s  origin=%s\n", f.Index, f.Path, f.Digest, f.Origin)
	}
	writeText(&b, "\nServices: %d\n", len(r.Services))
	for _, s := range r.Services {
		writeText(&b, "  %s  %s:%d:%d\n", s.Name, s.Location.File, s.Location.Line, s.Location.Column)
	}
	writeText(&b, "\nEnvironment sources (unresolved; not precedence): %d keys\n", len(r.Environment))
	for _, u := range r.UnappliedSources {
		writeText(&b, "  unapplied  %s  %s  applied=%v\n", u.Stage, u.Path, u.Applied)
	}
	for _, e := range r.Environment {
		label := e.Key
		if e.Secret {
			label += "  [redacted]"
		}
		writeText(&b, "  %s\n", label)
		for _, s := range e.Sources {
			loc := s.Stage
			if s.Path != nil {
				loc += "  " + *s.Path
			}
			if s.Line != nil {
				loc += fmt.Sprintf(":%d", *s.Line)
			}
			writeText(&b, "    %s  fingerprint=%s\n", loc, s.Fingerprint)
			if s.Reason != "" {
				writeText(&b, "    reason=%s\n", s.Reason)
			}
			if !s.Value.Redacted && s.Value.Text != nil {
				writeText(&b, "    value=%s\n", *s.Value.Text)
			}
		}
	}
	writeText(&b, "\nInterpolation (%s): %d values\n", r.InterpolationDisclaimer, len(r.Interpolation))
	for _, it := range r.Interpolation {
		writeText(&b, "  %s  %s:%d:%d  state=%s  form=%s\n", it.Path, it.Location.File, it.Location.Line, it.Location.Column, it.State, it.Form)
		writeText(&b, "    raw=%s\n", it.Raw)
		if it.Source != nil {
			loc := it.Source.Stage
			if loc == "" {
				loc = "unset"
			}
			if it.Source.Path != nil {
				loc += "  " + *it.Source.Path
			}
			if it.Source.Line != nil {
				loc += fmt.Sprintf(":%d", *it.Source.Line)
			}
			writeText(&b, "    source=%s  key=%s\n", loc, it.Source.Key)
		}
		if it.Value.Redacted {
			writeText(&b, "    value=[redacted]\n")
		} else if it.Value.Text != nil {
			writeText(&b, "    value=%s\n", *it.Value.Text)
		}
		if it.Error != nil {
			writeText(&b, "    error=%s\n", *it.Error)
		}
	}
	writeText(&b, "\nIncludes (%s): %d graphs\n", r.IncludesDisclaimer, len(r.Includes))
	for _, g := range r.Includes {
		formatIncludeGraph(&b, g, "  ")
	}
	writeText(&b, "\nExtends (%s): %d graphs\n", r.ExtendsDisclaimer, len(r.Extends))
	for _, g := range r.Extends {
		formatExtendsGraph(&b, g, "  ")
	}
	writeText(&b, "\nMerge (%s): %d fields\n", r.MergeDisclaimer, len(r.Merge))
	for _, f := range r.Merge {
		writeText(&b, "  %s  action=%s  winner=%s\n", f.Path, f.Action, f.Winner)
		if len(f.IncludeChain) > 1 {
			writeText(&b, "    include-chain=%s\n", strings.Join(f.IncludeChain, " -> "))
		}
		if f.ExtendsOrigin != "" {
			writeText(&b, "    extends-origin=%s", f.ExtendsOrigin)
			if f.ExtendsBaseService != "" {
				writeText(&b, "  base=%s", f.ExtendsBaseService)
			}
			if f.ExtendsBaseFile != "" {
				writeText(&b, "  file=%s", f.ExtendsBaseFile)
			}
			writeText(&b, "\n")
			if len(f.ExtendsChain) > 1 {
				writeText(&b, "    extends-chain=%s\n", strings.Join(f.ExtendsChain, " -> "))
			}
		}
		if f.Value.Redacted {
			writeText(&b, "    value=[redacted]\n")
		} else if f.Value.Text != nil {
			writeText(&b, "    value=%s\n", *f.Value.Text)
		}
		for _, o := range f.Overridden {
			ov := "[redacted]"
			if !o.Value.Redacted && o.Value.Text != nil {
				ov = *o.Value.Text
			} else if !o.Value.Redacted {
				ov = ""
			}
			writeText(&b, "    overridden  %s  action=%s  value=%s\n", o.File, o.Action, ov)
		}
	}
	writeText(&b, "\nProfiles (%s): %d active\n", r.ProfilesDisclaimer, len(r.ActiveProfiles))
	for _, a := range r.ActiveProfiles {
		name := a.Name
		if a.Redacted {
			name = "[redacted]"
		}
		writeText(&b, "  %s  source=%s\n", name, a.Source)
	}
	writeText(&b, "\nService profiles: %d\n", len(r.ProfileServices))
	for _, s := range r.ProfileServices {
		writeText(&b, "  %s  %s  %s  certainty=%s\n", s.Name, s.State, s.Reason, s.Certainty)
	}
	writeText(&b, "\nContainer environment (%s): %d services\n", r.ContainerEnvironmentDisclaimer, len(r.ContainerEnvironment))
	for _, se := range r.ContainerEnvironment {
		writeText(&b, "  service=%s  files=%d  vars=%d\n", se.Service, len(se.Files), len(se.Variables))
		for _, f := range se.Files {
			writeText(&b, "    env_file  path=%s  state=%s", dash(f.Path), dash(f.State))
			if f.Resolved != "" {
				writeText(&b, "  resolved=%s", f.Resolved)
			}
			if f.Reason != "" {
				writeText(&b, "  reason=%s", f.Reason)
			}
			writeText(&b, "\n")
		}
		for _, v := range se.Variables {
			writeText(&b, "    %s  state=%s  winner=%s", v.Key, v.State, v.Winner.Kind)
			if v.Winner.Path != "" {
				writeText(&b, "  path=%s", v.Winner.Path)
			}
			if v.Winner.Form != "" {
				writeText(&b, "  form=%s", v.Winner.Form)
			}
			writeText(&b, "\n")
			if v.Value.Redacted {
				writeText(&b, "      value=[redacted]\n")
			} else if v.State == "set" && v.Value.Text != nil {
				writeText(&b, "      value=%s\n", *v.Value.Text)
			}
			for _, o := range v.Overridden {
				ov := "[redacted]"
				if !o.Value.Redacted && o.Value.Text != nil {
					ov = *o.Value.Text
				} else if !o.Value.Redacted {
					ov = ""
				}
				writeText(&b, "      overridden  kind=%s  path=%s  value=%s\n", o.Kind, dash(o.Path), ov)
			}
		}
	}
	writeText(&b, "\nNormalization (%s): %d services\n", r.NormalizationDisclaimer, len(r.Normalization))
	for _, ns := range r.Normalization {
		writeText(&b, "  service=%s  ports=%d  volumes=%d  labels=%d\n", ns.Service, len(ns.Ports), len(ns.Volumes), len(ns.Labels))
		for _, p := range ns.Ports {
			writeText(&b, "    port  %s\n", formatNormItem(p))
		}
		for _, v := range ns.Volumes {
			writeText(&b, "    volume  %s\n", formatNormItem(v))
		}
		for _, l := range ns.Labels {
			writeText(&b, "    label  %s\n", formatNormItem(l))
		}
		if ns.Command != nil {
			writeText(&b, "    command  %s\n", formatNormItem(*ns.Command))
		}
		if ns.Entrypoint != nil {
			writeText(&b, "    entrypoint  %s\n", formatNormItem(*ns.Entrypoint))
		}
		if ns.Healthcheck != nil {
			writeText(&b, "    healthcheck  %s\n", formatNormItem(*ns.Healthcheck))
		}
	}
	return b.String()
}

func formatNormItem(it NormalizationItemReport) string {
	cert := it.Certainty
	if it.Reason != "" {
		cert += " (" + it.Reason + ")"
	}
	val := "[redacted]"
	if !it.Value.Redacted {
		val = it.Canonical
		if val == "" && it.Value.Text != nil {
			val = *it.Value.Text
		}
	}
	src := it.Source
	if src == "" {
		src = "-"
	}
	return "canonical=" + val + "  source=" + src + "  certainty=" + cert
}

func formatIncludeGraph(b *bytes.Buffer, g IncludeGraphReport, indent string) {
	writeText(b, "%s%s  hasCycle=%t\n", indent, g.File, g.HasCycle)
	for _, ref := range g.Refs {
		writeText(b, "%s  include  form=%s  path=%s  state=%s", indent, dash(ref.Form), dash(ref.Path), dash(ref.State))
		if ref.Resolved != "" {
			writeText(b, "  resolved=%s", ref.Resolved)
		}
		if ref.Reason != "" {
			writeText(b, "  reason=%s", ref.Reason)
		}
		if len(ref.UnsupportedFields) > 0 {
			writeText(b, "  extras=%s", strings.Join(ref.UnsupportedFields, ","))
		}
		writeText(b, "\n")
		if ref.Nested != nil {
			formatIncludeGraph(b, *ref.Nested, indent+"    ")
		}
	}
}

func formatExtendsGraph(b *bytes.Buffer, g ExtendsGraphReport, indent string) {
	writeText(b, "%s%s  hasCycle=%t\n", indent, g.File, g.HasCycle)
	for _, ref := range g.Refs {
		formatExtendsRef(b, ref, indent+"  ")
	}
}

func formatExtendsRef(b *bytes.Buffer, ref ExtendsRefReport, indent string) {
	writeText(b, "%sextends  service=%s  form=%s  state=%s", indent, dash(ref.Name), dash(ref.Form), dash(ref.State))
	if ref.Service != "" {
		writeText(b, "  target=%s", ref.Service)
	}
	if ref.Resolved != "" {
		writeText(b, "  resolved=%s", ref.Resolved)
	}
	if ref.Reason != "" {
		writeText(b, "  reason=%s", ref.Reason)
	}
	if len(ref.Excluded) > 0 {
		writeText(b, "  excluded=%s", strings.Join(ref.Excluded, ","))
	}
	writeText(b, "\n")
	if ref.Nested != nil {
		formatExtendsRef(b, *ref.Nested, indent+"  ")
	}
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func explainValueView(val string, secret bool) ValueView {
	v := ValueView{Redacted: secret}
	if secret {
		v.State = "redacted"
		return v
	}
	if val == "" {
		v.State = "empty"
		return v
	}
	v.State = "present"
	t := val
	v.Text = &t
	return v
}

func scrubExplain(s string, frags []string) string {
	if s == "" {
		return s
	}
	for _, frag := range frags {
		if frag != "" && strings.Contains(s, frag) {
			return "[redacted]"
		}
	}
	if redact.LooksLikeSecret(s) {
		return "[redacted]"
	}
	return s
}

// withholdLoser replaces the raw loser value that ends an Overridden line
// with the withheld placeholder when the stage is secret, keeping the
// kind/file and path label. Lines without a recorded value are unchanged.
func withholdLoser(line string, st explain.Stage, i int, secret bool) string {
	if !secret || i >= len(st.OverriddenValues) {
		return line
	}
	val := st.OverriddenValues[i]
	if val == "" || !strings.HasSuffix(line, val) {
		return line
	}
	return line[:len(line)-len(val)] + redact.TokenRedacted
}

func explainJSON(r explain.Result) explainReport {
	frags := explain.SecretFragments(r)
	stages := make([]explainStageReport, 0, len(r.Stages))
	for _, st := range r.Stages {
		secret := st.Secret || r.Secret
		ov := make([]string, 0, len(st.Overridden))
		for i, line := range st.Overridden {
			ov = append(ov, scrubExplain(withholdLoser(line, st, i, secret), frags))
		}
		rep := explainStageReport{
			Name:       st.Name,
			Summary:    st.Summary,
			Path:       st.Path,
			Value:      explainValueView(scrubExplain(st.Value, frags), secret && st.Value != ""),
			Raw:        explainValueView(scrubExplain(st.Raw, frags), secret && st.Raw != "" && !redact.RawReferenceShowable(st.Path, st.Raw)),
			State:      st.State,
			Source:     scrubExplain(st.Source, frags),
			Winner:     st.Winner,
			Origin:     st.Origin,
			Chain:      st.Chain,
			Overridden: ov,
			Secret:     secret,
			Certainty:  st.Certainty,
			Evidence:   st.Evidence,
			Reason:     scrubExplain(st.Reason, frags),
			Line:       st.Line,
			Column:     st.Column,
		}
		if len(ov) == 0 {
			rep.Overridden = nil
		}
		stages = append(stages, rep)
	}
	eff := explainValueView(scrubExplain(r.Effective, frags), r.Secret && r.Effective != "")
	if r.State == explain.StateAbsent {
		eff = ValueView{State: evidence.Absent}
	}
	return explainReport{
		Schema:     "composelens.explain.v0",
		Product:    version.Name,
		Version:    version.Version,
		Disclaimer: "single-target account composed from existing stage provenance — not a provenance graph",
		Target: explainTargetReport{
			Raw:     r.Target.Raw,
			Kind:    r.Target.Kind,
			Service: r.Target.Service,
			Path:    r.Target.Path,
			Key:     r.Target.Key,
		},
		State:      r.State,
		Reason:     r.Reason,
		Stages:     stages,
		Effective:  eff,
		Secret:     r.Secret,
		FinalStage: r.FinalStage,
		Certainty:  r.Certainty,
		Evidence:   r.Evidence,
	}
}

func writeValueView(b *bytes.Buffer, label string, v ValueView) {
	writeText(b, "%s", label)
	switch {
	case v.Redacted:
		writeText(b, "[redacted]\n")
	case v.Text != nil:
		writeText(b, "%s\n", *v.Text)
	default:
		writeText(b, "%s\n", dash(v.State))
	}
}

func formatExplain(r explain.Result) string {
	rep := explainJSON(r)
	var b bytes.Buffer
	writeText(&b, "ComposeLens explain — %s\n\n", rep.Disclaimer)
	writeText(&b, "target: %s  kind=%s\n", dash(rep.Target.Raw), dash(rep.Target.Kind))
	writeText(&b, "state: %s\n", rep.State)
	if rep.Reason != "" {
		writeText(&b, "reason: %s\n", rep.Reason)
	}
	if rep.FinalStage != "" {
		writeText(&b, "final-stage: %s\n", rep.FinalStage)
	}
	writeValueView(&b, "effective: ", rep.Effective)
	writeText(&b, "stages: %d\n", len(rep.Stages))
	for i, st := range rep.Stages {
		writeText(&b, "  %d. %s", i+1, st.Name)
		if st.Path != "" {
			writeText(&b, "  %s", st.Path)
		}
		if st.State != "" {
			writeText(&b, "  state=%s", st.State)
		}
		if st.Origin != "" {
			writeText(&b, "  origin=%s", st.Origin)
		}
		if st.Winner != "" {
			writeText(&b, "  winner=%s", st.Winner)
		}
		writeText(&b, "\n")
		if st.Summary != "" {
			writeText(&b, "     %s\n", st.Summary)
		}
		if st.Raw.Redacted || st.Raw.Text != nil {
			writeValueView(&b, "     raw=", st.Raw)
		}
		if st.Value.Redacted || st.Value.Text != nil {
			writeValueView(&b, "     value=", st.Value)
		}
		if st.Source != "" {
			writeText(&b, "     source=%s\n", st.Source)
		}
		if loc := stageLocation(st); loc != "" {
			writeText(&b, "     at=%s\n", loc)
		}
		if st.Reason != "" {
			writeText(&b, "     reason=%s\n", st.Reason)
		}
		if len(st.Chain) > 0 {
			writeText(&b, "     chain=%s\n", strings.Join(st.Chain, " -> "))
		}
		for _, o := range st.Overridden {
			writeText(&b, "     overridden: %s\n", o)
		}
		if st.Certainty != "" || st.Evidence != "" {
			writeText(&b, "     certainty=%s  evidence=%s\n", dash(st.Certainty), dash(st.Evidence))
		}
	}
	return b.String()
}

func nilStrings(ss []string) []string {
	if ss == nil {
		return []string{}
	}
	return ss
}

func diffJSON(leftP, rightP, leftEnv, rightEnv []string, r diff.Result) diffReport {
	frags := diff.SecretFragments(r)
	changes := make([]diffChangeReport, 0, len(r.Changes))
	for _, c := range r.Changes {
		secret := c.Secret
		changes = append(changes, diffChangeReport{
			Target: c.Target,
			Kind:   c.Kind,
			Change: c.Change,
			Left:   diffSideJSON(c.Left, secret, frags),
			Right:  diffSideJSON(c.Right, secret, frags),
			Secret: secret,
		})
	}
	return diffReport{
		Schema:     "composelens.diff.v0",
		Product:    version.Name,
		Version:    version.Version,
		Disclaimer: "effective-config delta over the same Compose files — not a provenance graph, not an engine differential",
		Left:       diffSelectionReport{Profiles: nilStrings(leftP), EnvFiles: nilStrings(leftEnv)},
		Right:      diffSelectionReport{Profiles: nilStrings(rightP), EnvFiles: nilStrings(rightEnv)},
		Changes:    changes,
		Empty:      len(changes) == 0,
		Evidence:   r.Evidence,
		Certainty:  r.Certainty,
	}
}

func diffSideJSON(sv diff.SideValue, secret bool, frags []string) diffSideReport {
	if !sv.Present {
		return diffSideReport{Present: false, Value: ValueView{State: evidence.Absent}}
	}
	hide := secret || sv.Secret
	val := sv.Effective
	if hide {
		val = ""
	} else {
		val = scrubExplain(val, frags)
	}
	return diffSideReport{
		Present: true,
		Value:   explainValueView(val, hide),
		Source:  scrubExplain(sv.Source, frags),
		State:   sv.State,
	}
}

func formatDiff(leftP, rightP, leftEnv, rightEnv []string, r diff.Result) string {
	rep := diffJSON(leftP, rightP, leftEnv, rightEnv, r)
	var b bytes.Buffer
	writeText(&b, "ComposeLens diff — %s\n\n", rep.Disclaimer)
	writeText(&b, "left:  profiles=%s  env-files=%s\n", dashJoin(rep.Left.Profiles), dashJoin(rep.Left.EnvFiles))
	writeText(&b, "right: profiles=%s  env-files=%s\n", dashJoin(rep.Right.Profiles), dashJoin(rep.Right.EnvFiles))
	writeText(&b, "changes: %d\n", len(rep.Changes))
	if rep.Empty {
		writeText(&b, "  (empty)\n")
		return b.String()
	}
	for i, c := range rep.Changes {
		writeText(&b, "  %d. %s  %s  %s", i+1, c.Change, c.Kind, c.Target)
		if c.Secret {
			writeText(&b, "  [redacted] (changed by presence)\n")
		} else {
			writeText(&b, "\n")
			writeValueView(&b, "     left=", c.Left.Value)
			writeValueView(&b, "     right=", c.Right.Value)
		}
		if c.Left.Source != "" || c.Right.Source != "" {
			writeText(&b, "     left-source=%s  right-source=%s\n", dash(c.Left.Source), dash(c.Right.Source))
		}
		if c.Left.State != "" || c.Right.State != "" {
			writeText(&b, "     left-state=%s  right-state=%s\n", dash(c.Left.State), dash(c.Right.State))
		}
	}
	return b.String()
}

func dashJoin(ss []string) string {
	if len(ss) == 0 {
		return "-"
	}
	return strings.Join(ss, ",")
}

var implementedFeatures = []string{
	"doctor",
	"inspect-source-level",
	"version",
	"file-discovery",
	"yaml-json-source-ranges",
	"path-resolution",
	"env-source-labeling",
	"secret-redaction",
	"interpolation-engine",
	"multi-file-merge",
	"service-profiles",
	"compose-include",
	"service-extends",
	"container-environment-precedence",
	"explain",
	"diff",
	"check",
	"provenance-graph",
	"shadow-chains",
	"canonical-normalization",
	"fixture-taxonomy",
	"compose-engine-adapter",
	"compose-engine-capability",
	"compose-engine-differential",
	"compose-reproduction",
	"compose-policy-loading",
	"redaction-config",
	"report-data-package",
	"static-html-report",
	"interactive-html-report",
	"accessible-html-report",
	"html-report-csp",
}

var deferredFeatures = []string{
	"recursive-interpolation",
	"policy-engine",
	"sarif-upload",
	"github-action-live",
	"github-publication",
}

const (
	skipNoEngine      = "--no-engine: no engine command was run"
	skipRemoteInclude = "remote include: the engine would resolve it over the network; pass --allow-network to allow it"
)

// engineCapture runs the local `docker compose config` capture for report and
// differential. ComposeLens itself makes no network calls; a selection with a
// remote include (OCI, Git or HTTP) would make the engine resolve it over the
// network, so the capture is skipped unless --allow-network is given.
// --no-engine skips the capture entirely.
func (rt Runtime) engineCapture(opt Options, req engineadapter.Request, includes []IncludeGraphReport, b *safety.Budget) engineadapter.Result {
	if opt.NoEngine {
		return engineadapter.Skipped(skipNoEngine)
	}
	if !opt.AllowNetwork && hasRemoteInclude(includes) {
		return engineadapter.Skipped(skipRemoteInclude)
	}
	runner := engineadapter.DefaultRunner()
	if rt.EngineRunner != nil {
		runner = rt.EngineRunner()
	}
	return runner.WithBudget(b).Capture(context.Background(), req)
}

func hasRemoteInclude(graphs []IncludeGraphReport) bool {
	for _, g := range graphs {
		for _, r := range g.Refs {
			if include.IsRemote(r.Path) {
				return true
			}
			if r.Nested != nil && hasRemoteInclude([]IncludeGraphReport{*r.Nested}) {
				return true
			}
		}
	}
	return false
}

func skipReason(cap engineadapter.Result) string {
	if cap.State == engineadapter.StateSkipped {
		return cap.Detail
	}
	return ""
}

// findingNodes resolves each check finding to its one provenance-graph node,
// so the report viewer opens the right source chain (nil when none resolves).
func findingNodes(g provgraph.Graph, r check.Result) []*check.NodeRef {
	out := make([]*check.NodeRef, len(r.Findings))
	for i, f := range r.Findings {
		if n, ok := provgraph.FindingNode(g, f.Target, f.Kind, f.File); ok {
			out[i] = &check.NodeRef{Target: n.Target, Kind: n.Kind}
		}
	}
	return out
}

// stageLocation is FILE:LINE[:COLUMN] of a stage's winning source, or "".
func stageLocation(st explainStageReport) string {
	file := st.Source
	if file == "" {
		file = st.Winner
	}
	if file == "" || st.Line <= 0 {
		return ""
	}
	loc := fmt.Sprintf("%s:%d", file, st.Line)
	if st.Column > 0 {
		loc += fmt.Sprintf(":%d", st.Column)
	}
	return loc
}
