// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
)

const fingerprintKeySize = 32

var keyNeedles = []string{
	"PASSWORD", "PASSWD", "SECRET", "TOKEN", "APIKEY", "API_KEY",
	"PRIVATE_KEY", "ACCESS_KEY", "SECRET_KEY", "CREDENTIAL",
	"AUTHORIZATION", "AUTH_TOKEN", "PASSPHRASE", "BEARER",
}

var (
	reAWS       = regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)
	reGitHub    = regexp.MustCompile(`\b(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{20,}\b`)
	reGitHubPat = regexp.MustCompile(`\bgithub_pat_[A-Za-z0-9_]{20,}\b`)
	reSlack     = regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,}\b`)
	reJWT       = regexp.MustCompile(`\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b`)
	rePEM       = regexp.MustCompile(`-----BEGIN [A-Z ]*PRIVATE KEY-----`)
	reUserinfo  = regexp.MustCompile(`(?i)[a-z][a-z0-9+.-]*://[^/@\s]+:[^/@\s]+@`)
	reConnPass  = regexp.MustCompile(`(?i)(?:^|[;\s])(?:password|passwd|pwd)\s*=\s*([^\s;]+)`)
)

type Fingerprinter struct {
	key []byte
}

// NewFingerprinter creates a per-run HMAC-SHA256 fingerprinter. The key is
// 32 bytes from crypto/rand, never emitted, and not correlatable across runs.
func NewFingerprinter() (*Fingerprinter, error) {
	return NewFingerprinterFrom(rand.Reader)
}

func NewFingerprinterFrom(r io.Reader) (*Fingerprinter, error) {
	if r == nil {
		return nil, fmt.Errorf("fingerprint key generation failed")
	}
	key := make([]byte, fingerprintKeySize)
	if _, err := io.ReadFull(r, key); err != nil {
		return nil, fmt.Errorf("fingerprint key generation failed")
	}
	out := &Fingerprinter{key: key}
	return out, nil
}

func (f *Fingerprinter) Fingerprint(value string) string {
	mac := hmac.New(sha256.New, f.key)
	_, _ = mac.Write([]byte(value))
	sum := mac.Sum(nil)
	return "hmac-sha256:" + hex.EncodeToString(sum[:16])
}

func (f *Fingerprinter) GuardMaterial() []string {
	if f == nil || len(f.key) == 0 {
		return nil
	}
	return []string{string(f.key), hex.EncodeToString(f.key)}
}

func NormalizeKey(key string) string {
	var out strings.Builder
	var prev rune
	for _, r := range key {
		if unicode.IsUpper(r) && unicode.IsLower(prev) {
			out.WriteByte('_')
		}
		if r == '-' {
			r = '_'
		}
		out.WriteRune(unicode.ToUpper(r))
		prev = r
	}
	return out.String()
}

func IsSecretKey(key string) bool {
	if c := current(); c != nil {
		if c.allowKey(key) {
			return false
		}
		if c.extraKey(key) {
			return true
		}
	}
	return isSecretKeyDefault(key)
}

func isSecretKeyDefault(key string) bool {
	u := NormalizeKey(key)
	if u == "" {
		return false
	}
	if settingKey(u) {
		return false
	}
	for _, n := range keyNeedles {
		if strings.Contains(u, n) {
			return true
		}
	}
	if u == "KEY" || strings.HasPrefix(u, "KEY_") || strings.HasSuffix(u, "_KEY") || strings.Contains(u, "_KEY_") {
		return true
	}
	if u == "PWD" || strings.HasPrefix(u, "PWD_") || strings.HasSuffix(u, "_PWD") || strings.Contains(u, "_PWD_") {
		return true
	}
	return tokenKeySecret(u)
}

func LooksLikeSecret(value string) bool {
	if value == "" {
		return false
	}
	if c := current(); c != nil {
		if c.allowVal(value) {
			return false
		}
		if c.extraVal(value) {
			return true
		}
	}
	return looksLikeSecretDefault(value)
}

func looksLikeSecretDefault(value string) bool {
	if value == "" {
		return false
	}
	if rePEM.MatchString(value) || reAWS.MatchString(value) || reGitHub.MatchString(value) ||
		reGitHubPat.MatchString(value) || reSlack.MatchString(value) || reJWT.MatchString(value) {
		return true
	}
	if hasEmbeddedCredentials(value) {
		return true
	}
	if publicIdentifier(value) {
		return false
	}
	if credentialFreeURL(value) {
		return false
	}
	if genuineFilesystemPath(value) {
		return false
	}
	if len(secretParts(value)) > 0 {
		return true
	}
	return highEntropyToken(value) || randomAlnumToken(value)
}

// provenanceLabels are role/stage prefixes ComposeLens prepends to file paths
// in human provenance (check CHK05, graph shadow-chain sources). They are not
// part of the filesystem path itself.
var provenanceLabels = map[string]struct{}{
	"winner": {}, "loser": {}, "environment": {}, "env-file": {},
	"project-env": {}, "host-shell": {}, "file": {}, "include": {},
	"extends": {}, "profiles": {}, "interpolation": {}, "merge": {},
	"container-environment": {},
}

func stripProvenanceLabels(s string) string {
	for {
		i := strings.IndexByte(s, ':')
		if i < 2 {
			return s
		}
		label := strings.ToLower(s[:i])
		if _, ok := provenanceLabels[label]; !ok {
			return s
		}
		s = s[i+1:]
	}
}

func genuineFilesystemPath(value string) bool {
	v := strings.TrimSpace(value)
	if v == "" || strings.Contains(v, "://") {
		return false
	}
	v = stripProvenanceLabels(v)
	if v == "" || strings.Contains(v, "://") {
		return false
	}
	if !hasPathShape(v) {
		return false
	}
	for _, seg := range pathSegments(v) {
		if secretPathSegment(seg) {
			return false
		}
	}
	return true
}

func hasPathShape(v string) bool {
	lower := strings.ToLower(v)
	extOK := strings.HasSuffix(lower, ".env") || strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml")
	if !strings.ContainsAny(v, `/\`) {
		return extOK
	}
	if len(v) >= 3 {
		r0 := rune(v[0])
		if unicode.IsLetter(r0) && v[1] == ':' && (v[2] == '\\' || v[2] == '/') {
			return true
		}
	}
	if strings.HasPrefix(v, `\\`) || strings.HasPrefix(v, "/") || strings.HasPrefix(v, "./") || strings.HasPrefix(v, "../") {
		return true
	}
	return extOK || strings.ContainsAny(v, `/\`)
}

func pathSegments(v string) []string {
	v = strings.ReplaceAll(v, `\`, "/")
	raw := strings.Split(v, "/")
	out := make([]string, 0, len(raw))
	for _, p := range raw {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func secretPathSegment(seg string) bool {
	if seg == "" || seg == "." || seg == ".." {
		return false
	}
	if len(seg) == 2 && seg[1] == ':' && unicode.IsLetter(rune(seg[0])) {
		return false
	}
	if rePEM.MatchString(seg) || reAWS.MatchString(seg) || reGitHub.MatchString(seg) ||
		reGitHubPat.MatchString(seg) || reSlack.MatchString(seg) || reJWT.MatchString(seg) {
		return true
	}
	if hasEmbeddedCredentials(seg) {
		return true
	}
	name := seg
	if i := strings.LastIndex(seg, "."); i > 0 {
		name = seg[:i]
	}
	if IsSecretKey(name) || IsSecretKey(seg) {
		return true
	}
	return highEntropyToken(seg) && !wordStructured(seg)
}

// wordStructured reports whether a path segment is built from separated
// words, numbers and short mixed runs (for example a scratch folder
// "project_snapshot_12345678_4b7d2e9c" or "project-cache-12345678-part-17").
// Such names are ordinary provenance; a secret-shaped segment carries a long
// run that mixes letters and digits, or other symbols. Recognized vendor
// tokens are matched before this check and stay secret.
func wordStructured(seg string) bool {
	pieces := strings.FieldsFunc(seg, func(r rune) bool { return r == '_' || r == '-' || r == '.' || r == ' ' })
	for _, piece := range pieces {
		letters, digits := 0, 0
		for _, r := range piece {
			switch {
			case unicode.IsLetter(r):
				letters++
			case unicode.IsDigit(r):
				digits++
			default:
				return false
			}
		}
		if letters > 0 && digits > 0 && len(piece) > 12 {
			return false
		}
	}
	return true
}

func credentialFreeURL(value string) bool {
	u, err := url.Parse(value)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return false
	}
	return true
}

func hasEmbeddedCredentials(value string) bool {
	if u, err := url.Parse(value); err == nil {
		if u.User != nil {
			if pass, set := u.User.Password(); set && pass != "" {
				return true
			}
		}
	}
	for _, p := range queryPairs(value) {
		if p.secret && strings.TrimSpace(p.value) != "" {
			return true
		}
	}
	if reUserinfo.MatchString(value) {
		return true
	}
	return reConnPass.MatchString(value)
}

func SecretFragments(value string) []string {
	seen := map[string]struct{}{}
	var out []string
	add := func(s string) {
		if s == "" {
			return
		}
		if _, ok := seen[s]; ok {
			return
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	add(value)
	if u, err := url.Parse(value); err == nil {
		if u.User != nil {
			if pass, set := u.User.Password(); set {
				add(pass)
			}
		}
	}
	for _, p := range queryPairs(value) {
		if p.secret {
			add(p.value)
			add(p.decoded)
		}
	}
	for _, m := range reConnPass.FindAllStringSubmatch(value, -1) {
		if len(m) > 1 {
			add(m[1])
		}
	}
	for _, p := range secretParts(value) {
		add(p)
	}
	return out
}

func highEntropyToken(value string) bool {
	v := strings.TrimSpace(value)
	v = strings.TrimSpace(stripComposeInterpolation(v))
	if len(v) < 24 {
		return false
	}
	if strings.ContainsAny(v, " \t\n") {
		return false
	}
	letters, digits, other := 0, 0, 0
	for _, r := range v {
		switch {
		case unicode.IsLetter(r):
			letters++
		case unicode.IsDigit(r):
			digits++
		default:
			other++
		}
	}
	classes := 0
	if letters > 0 {
		classes++
	}
	if digits > 0 {
		classes++
	}
	if other > 0 {
		classes++
	}
	return classes >= 3 && len(v) >= 32
}

func stripComposeInterpolation(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	i := 0
	for i < len(s) {
		if s[i] == '$' && i+1 < len(s) {
			next := s[i+1]
			if next == '$' {
				i += 2
				continue
			}
			if next == '{' {
				if end := strings.IndexByte(s[i+2:], '}'); end >= 0 {
					i = i + 2 + end + 1
					continue
				}
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func MustRedact(key, value string) bool {
	if publicSignal(key, value) || (!IsSecretKey(key) && publicRevision(key, value)) {
		return false
	}
	return IsSecretKey(key) || LooksLikeSecret(value)
}

func FlagName(arg string) string {
	if i := strings.IndexByte(arg, '='); i >= 0 {
		return arg[:i]
	}
	return arg
}

// baseName is the last path element for either separator, so a Windows path
// is read the same on every platform.
func baseName(s string) string {
	t := strings.TrimRight(s, `/\`)
	if t == "" {
		return s
	}
	if i := strings.LastIndexAny(t, `/\`); i >= 0 {
		return t[i+1:]
	}
	return t
}

func ShouldHideDiagnostic(s string) bool {
	if s == "" {
		return false
	}
	if strings.Contains(s, "://") {
		return LooksLikeSecret(s)
	}
	base := baseName(s)
	name := base
	if dot := strings.LastIndex(name, "."); dot > 0 {
		name = name[:dot]
	}
	if IsSecretKey(name) || IsSecretKey(base) {
		return true
	}
	if LooksLikeSecret(name) || LooksLikeSecret(base) {
		return true
	}
	if !strings.ContainsAny(s, `/\`) && LooksLikeSecret(s) {
		return true
	}
	return false
}

func DiagnosticLabel(s string) string {
	if ShouldHideDiagnostic(s) || ContainsStrongToken(s) {
		return "<redacted>"
	}
	return s
}

func RedactInError(err error, values ...string) error {
	if err == nil {
		return nil
	}
	msg := err.Error()
	orig := msg
	for _, v := range values {
		if v == "" {
			continue
		}
		hide := ShouldHideDiagnostic(v)
		base := baseName(v)
		if !hide && base != v {
			hide = ShouldHideDiagnostic(base)
		}
		if !hide {
			continue
		}
		repls := []string{v, filepath.ToSlash(v), strings.ReplaceAll(v, `\`, `\\`), base}
		for _, c := range repls {
			if c != "" && strings.Contains(msg, c) {
				msg = strings.ReplaceAll(msg, c, "<redacted>")
			}
		}
	}
	if msg == orig {
		return err
	}
	return fmt.Errorf("%s", msg)
}

type queryPair struct {
	value   string // raw bytes as written
	decoded string // percent-decoded; equal to value when it cannot be decoded
	secret  bool   // the key (raw or decoded) is a credential key
}

// queryPairs scans the query of a URL-shaped value without dropping anything:
// every repeated key is kept, both '&' and ';' separate pairs, and a pair
// whose escapes cannot be decoded keeps its raw bytes. url.Values would keep
// only the first value and silently drop malformed pairs.
func queryPairs(value string) []queryPair {
	i := strings.IndexByte(value, '?')
	if i < 0 || !strings.Contains(value[:i], "://") {
		return nil
	}
	q := value[i+1:]
	if h := strings.IndexByte(q, '#'); h >= 0 {
		q = q[:h]
	}
	var out []queryPair
	for _, part := range strings.FieldsFunc(q, func(r rune) bool { return r == '&' || r == ';' }) {
		key, val, _ := strings.Cut(part, "=")
		dk, err := url.QueryUnescape(key)
		if err != nil {
			dk = key
		}
		dv, err := url.QueryUnescape(val)
		if err != nil {
			dv = val
		}
		out = append(out, queryPair{value: val, decoded: dv, secret: IsSecretKey(key) || IsSecretKey(dk)})
	}
	return out
}

// strongTokens are recognized vendor credential patterns. They are protected
// wherever they appear — argv, any path segment, OS errors, engine metadata —
// independently of the broad entropy heuristic, so ordinary long paths stay
// readable while a recognized token never prints.
var strongTokens = []*regexp.Regexp{rePEM, reAWS, reGitHub, reGitHubPat, reSlack, reJWT}

// ContainsStrongToken reports whether s contains a recognized vendor token.
func ContainsStrongToken(s string) bool {
	for _, re := range strongTokens {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}

// ScrubStrongTokens replaces every recognized vendor token in s with the
// withheld placeholder.
func ScrubStrongTokens(s string) string {
	for _, re := range strongTokens {
		s = re.ReplaceAllString(s, TokenRedacted)
	}
	return s
}

// ScrubErrorTokens withholds recognized vendor tokens in an error message
// while keeping the original error reachable for typed diagnostics.
func ScrubErrorTokens(err error) error {
	if err == nil || !ContainsStrongToken(err.Error()) {
		return err
	}
	return &scrubbedError{msg: ScrubStrongTokens(err.Error()), err: err}
}

type scrubbedError struct {
	msg string
	err error
}

func (e *scrubbedError) Error() string { return e.msg }
func (e *scrubbedError) Unwrap() error { return e.err }
