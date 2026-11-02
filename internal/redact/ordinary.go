// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"regexp"
	"strconv"
	"strings"
)

var (
	reHexRevision   = regexp.MustCompile(`^[0-9a-fA-F]{40}$`)
	reImageRevision = regexp.MustCompile(`^[A-Za-z0-9_./:-]+:[0-9a-fA-F]{40}$`)
	reUUID          = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reDigest        = regexp.MustCompile(`(?i)(?:^|@)(?:sha1|sha224|sha256|sha384|sha512|md5):[0-9a-f]+$`)
	reSignal        = regexp.MustCompile(`^SIG[A-Z0-9]+$`)
)

func publicIdentifier(value string) bool {
	return reUUID.MatchString(value) || reImageRevision.MatchString(value) || reDigest.MatchString(value)
}

func publicRevision(key, value string) bool {
	if !reHexRevision.MatchString(value) {
		return false
	}
	parts := strings.FieldsFunc(NormalizeKey(key), func(r rune) bool { return r == '_' || r == '.' })
	for _, word := range parts {
		switch word {
		case "COMMIT", "REVISION", "SHA", "TAG":
			return true
		}
	}
	return false
}

// PublicRevision reports a revision-shaped value in a non-secret field.
func PublicRevision(key, value string) bool {
	return !SecretPath(key) && (publicRevision(key, value) || reImageRevision.MatchString(value))
}

func publicSignal(key, value string) bool {
	parts := pathKeys(key)
	if len(parts) == 0 {
		return false
	}
	key = NormalizeKey(parts[len(parts)-1])
	if i := strings.LastIndexByte(key, ':'); i >= 0 {
		key = key[i+1:]
	}
	if key != "KILL_SIG" && key != "STOP_SIG" && key != "SIGNAL" && key != "STOP_SIGNAL" {
		return false
	}
	return reSignal.MatchString(value)
}

// OrdinaryShortOption identifies a short boolean or number under a key that
// does not explicitly name credential material. It stays withheld when its
// broader path is sensitive, but does not require a byte-scan refusal.
func OrdinaryShortOption(key, value string) bool {
	if len(value) == 0 || len(value) >= 6 || LooksLikeSecret(value) {
		return false
	}
	u := NormalizeKey(key)
	for _, needle := range keyNeedles {
		if strings.Contains(u, needle) {
			return false
		}
	}
	if u == "KEY" || u == "PWD" || u == "PW" || u == "PASS" {
		return false
	}
	switch strings.ToLower(value) {
	case "on", "off", "true", "false", "yes", "no":
		return true
	}
	_, err := strconv.ParseFloat(value, 64)
	return err == nil
}
