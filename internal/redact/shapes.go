// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"math"
	"regexp"
	"strings"
	"unicode"
)

// tokenNeedles are secret names that are too short or too common to match
// as substrings (SIG would match STOP_SIGNAL, PASS would match BYPASS). They
// count as words anywhere in a key: SMTP_PASS_PROD, URL_SIG, DSN_PRIMARY.
var tokenNeedles = map[string]struct{}{
	"PASS": {}, "PW": {}, "PWD": {}, "AUTH": {}, "SIG": {}, "SIGNING": {}, "SIGNATURE": {},
	"COOKIE": {}, "DSN": {}, "SALT": {},
}

// passWords end in PASS but are ordinary words.
var passWords = map[string]struct{}{
	"BYPASS": {}, "COMPASS": {}, "SURPASS": {}, "TRESPASS": {}, "OVERPASS": {}, "UNDERPASS": {},
}

// tokenKeySecret checks words in a normalized upper-case, underscore key.
func tokenKeySecret(u string) bool {
	words := strings.FieldsFunc(u, func(r rune) bool { return r == '_' || r == '.' })
	if len(words) == 0 {
		return false
	}
	// These key combinations name options rather than credential values.
	if u == "COOKIE_SECURE" || u == "COOKIE_DOMAIN" || u == "DSN_TIMEOUT" || u == "PASS_THROUGH_MODE" || u == "FIRST_PASS" {
		return false
	}
	for _, word := range words {
		if _, ok := tokenNeedles[word]; ok {
			return true
		}
		if len(word) > len("PASS") && strings.HasSuffix(word, "PASS") {
			if _, ordinary := passWords[word]; !ordinary {
				return true
			}
		}
	}
	return false
}

// referenceWords end a secret-named key whose value names a secret rather
// than holding it (--token-file /run/secrets/token).
var referenceWords = map[string]struct{}{
	"FILE": {}, "PATH": {}, "DIR": {}, "ENV": {}, "NAME": {},
}

// partKeySecret reports whether the key of a KEY=VALUE word or the name of a
// flag holds a secret: "--password", "-Djavax.net.ssl.keyStorePassword",
// "API_KEY". Keys that only reference a secret (…_FILE, …_PATH) do not.
func partKeySecret(k string) bool {
	if strings.HasPrefix(k, "-D") && len(k) > 2 {
		k = k[2:]
	}
	k = strings.TrimLeft(k, "-")
	if i := strings.LastIndexByte(k, '.'); i >= 0 {
		k = k[i+1:]
	}
	if k == "" || !IsSecretKey(k) {
		return false
	}
	words := strings.FieldsFunc(NormalizeKey(k), func(r rune) bool { return r == '_' })
	if len(words) > 1 {
		if _, ref := referenceWords[words[len(words)-1]]; ref {
			return false
		}
	}
	return true
}

// SecretFlag reports whether arg is a command-line flag without an attached
// value whose name holds a secret ("--token", "-password"). The argument
// after such a flag is the secret.
func SecretFlag(arg string) bool {
	if !strings.HasPrefix(arg, "-") || strings.ContainsAny(arg, "= \t") {
		return false
	}
	name := strings.TrimLeft(arg, "-")
	if name == "" || !unicode.IsLetter(rune(name[0])) {
		return false
	}
	return partKeySecret(arg)
}

var (
	reHeader = regexp.MustCompile(`^\s*([A-Za-z][A-Za-z0-9-]*)\s*:\s*(\S.*?)\s*$`)
	reScheme = regexp.MustCompile(`(?i)\b(?:bearer|basic)\s+([A-Za-z0-9._~+/=-]{8,})`)
)

// secretParts returns the secret pieces of a value read as words: a
// KEY=VALUE word with a secret key, the word after a secret-named flag, an
// HTTP header with a secret name ("Authorization: …"), the credential after
// "Bearer"/"Basic", and any word that is itself secret-shaped.
func secretParts(value string) []string {
	var out []string
	if m := reHeader.FindStringSubmatch(value); m != nil && IsSecretKey(m[1]) {
		out = append(out, m[2])
	}
	for _, m := range reScheme.FindAllStringSubmatch(value, -1) {
		out = append(out, m[1])
	}
	words := strings.Fields(value)
	for i, w := range words {
		if i+1 < len(words) && userFlag(w) && credentialArgument(words[i+1]) {
			arg := strings.Trim(words[i+1], `"'`)
			out = append(out, arg, arg[strings.IndexByte(arg, ':')+1:])
			continue
		}
		if k, v, ok := strings.Cut(w, "="); ok && v != "" && !strings.EqualFold(k, "key") && partKeySecret(k) {
			out = append(out, strings.Trim(v, `"'`))
			continue
		}
		if i+1 < len(words) && (SecretFlag(w) || (w == "-p" && databaseCommand(words[:i]))) && argValue(words[i+1]) {
			out = append(out, strings.Trim(words[i+1], `"'`))
			continue
		}
		if len(words) > 1 && looksLikeSecretWord(w) {
			out = append(out, w)
		}
	}
	return out
}

// looksLikeSecretWord classifies one whitespace-free word of a longer value.
func looksLikeSecretWord(w string) bool {
	w = strings.Trim(w, `"'`)
	if w == "" {
		return false
	}
	if ContainsStrongToken(w) || hasEmbeddedCredentials(w) {
		return true
	}
	if credentialFreeURL(w) || hasPathShape(w) {
		// A path word is shown unless it carries a vendor token or embedded
		// credentials (above); folder names are not entropy-tested here.
		return false
	}
	return highEntropyToken(w) || randomAlnumToken(w)
}

// minRandomLen and minRandomSwitches describe a generated token: at least 24
// letters and digits that switch between letters and digits often. A word
// followed by a number ("BuildCache2026") switches once; hex keys and
// base64-style tokens switch many times.
const (
	minRandomLen      = 24
	minRandomSwitches = 6
)

// randomAlnumToken reports a long run of letters and digits shaped like a
// generated key: a mixed token with enough length, variation and entropy.
func randomAlnumToken(value string) bool {
	v := strings.TrimSpace(stripComposeInterpolation(strings.TrimSpace(value)))
	if len(v) < minRandomLen {
		return false
	}
	return randomRun(v)
}

// randomRun checks alphanumeric switching and mixed-case letter runs.
func randomRun(s string) bool {
	letters, digits, switches, caseSwitches := 0, 0, 0, 0
	upper, lower, priorCase := 0, 0, 0
	prev := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		cls := 0
		switch {
		case c >= '0' && c <= '9':
			cls = 1
			digits++
		case (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'):
			cls = 2
			letters++
			currentCase := 1
			if c >= 'A' && c <= 'Z' {
				upper++
				currentCase = 2
			} else {
				lower++
			}
			if priorCase != 0 && priorCase != currentCase {
				caseSwitches++
			}
			priorCase = currentCase
		default:
			return false
		}
		if prev != 0 && cls != prev {
			switches++
		}
		prev = cls
	}
	if letters > 0 && digits > 0 && switches >= minRandomSwitches {
		return len(s) >= 32 || (len(s) >= 24 && entropy(s) >= 3.5)
	}
	return len(s) >= 32 && digits == 0 && upper*4 >= len(s) && lower*4 >= len(s) && caseSwitches >= 12 && entropy(s) >= 4.1
}

func entropy(s string) float64 {
	counts := map[byte]int{}
	for i := range len(s) {
		counts[s[i]]++
	}
	var h float64
	for _, n := range counts {
		p := float64(n) / float64(len(s))
		h -= p * math.Log2(p)
	}
	return h
}

func userFlag(flag string) bool { return flag == "-u" || flag == "--user" }

func credentialArgument(value string) bool {
	value = strings.Trim(value, `"'`)
	i := strings.IndexByte(value, ':')
	return i > 0 && i < len(value)-1
}

func databaseCommand(words []string) bool {
	for _, word := range words {
		switch strings.ToLower(baseName(strings.Trim(word, `"'`))) {
		case "mysql", "mariadb", "psql", "redis-cli", "mongosh", "mongo":
			return true
		}
	}
	return false
}

// SecretFlagValue applies argv-pair rules to list items. Numeric port values
// following -p are ordinary; -u/--user require a user:password pair.
func SecretFlagValue(flag, value string) bool {
	if userFlag(flag) {
		return credentialArgument(value)
	}
	if flag == "-p" {
		for _, r := range value {
			if r < '0' || r > '9' {
				return argValue(value)
			}
		}
		return false
	}
	return SecretFlag(flag) && argValue(value)
}

// digestPrefixes mark a hex or base64 run as a content digest or a
// ComposeLens fingerprint rather than a credential.
var digestPrefixes = []string{
	"sha1:", "sha224:", "sha256:", "sha384:", "sha512:", "md5:", "hmac-sha256:",
	"sha256-", "sha384-", "sha512-",
}

// SecretShapedRun returns the first run of letters and digits in s that is
// shaped like a generated credential and is not a labelled digest
// ("sha256:…", "hmac-sha256:…"). The empty string means none.
func SecretShapedRun(s string) string {
	i := 0
	for i < len(s) {
		if !isAlnumByte(s[i]) {
			i++
			continue
		}
		j := i
		for j < len(s) && isAlnumByte(s[j]) {
			j++
		}
		if j-i >= minRandomLen && randomRun(s[i:j]) && !digestLabelled(s, i) {
			return s[i:j]
		}
		i = j
	}
	return ""
}

func isAlnumByte(c byte) bool {
	return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func digestLabelled(s string, start int) bool {
	// Walk back over the rest of a base64 digest ("sha384-AbC+dEf/…") so a
	// run after "+" or "/" inside it is still labelled.
	for start > 0 && (isAlnumByte(s[start-1]) || s[start-1] == '+' || s[start-1] == '/' || s[start-1] == '=') {
		start--
	}
	head := strings.ToLower(s[:start])
	for _, p := range digestPrefixes {
		if strings.HasSuffix(head, p) {
			return true
		}
	}
	return false
}

// argValue reports whether the word after a flag is a value rather than
// another flag, a placeholder ("<KEY>", "[VALUE]") or an unexpanded
// variable reference.
func argValue(w string) bool {
	w = strings.Trim(w, `"'`)
	return w != "" && !strings.ContainsAny(w[:1], "-<[{$")
}

// ContainsSecretMaterial reports whether a stored text (a fixture, a
// document) holds credential material itself: a recognized vendor token,
// embedded credentials (URL userinfo, a credential query key, a
// connection-string password), or a run shaped like a generated key. A
// placeholder under a secret-named key ("API_TOKEN=demo-inline") is not
// material.
func ContainsSecretMaterial(text string) bool {
	return ContainsStrongToken(text) || hasEmbeddedCredentials(text) || SecretShapedRun(text) != ""
}
