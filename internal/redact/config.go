// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"regexp"
	"sync"
)

const (
	Schema = "composelens.redact.v0"
	// DiscoveredName is loaded from the project directory when --redact is omitted.
	DiscoveredName = "composelens.redact.yaml"

	DisplayFingerprint DisplayMode = "fingerprint"
	DisplayRedacted    DisplayMode = "redacted"

	// TokenRedacted is the irreversible withheld placeholder. It is not an encoding
	// of the raw value and cannot be reversed.
	TokenRedacted = "[redacted]"

	maxListEntries  = 32
	maxPatternBytes = 256
	maxConfigDepth  = 64
	maxConfigNodes  = 50_000
)

type DisplayMode string

// Config is a schema-validated redaction overlay. Nil / Reset preserves defaults.
type Config struct {
	Schema  string
	Display DisplayMode

	extraKeys   []*regexp.Regexp
	extraValues []*regexp.Regexp
	allowKeys   map[string]struct{}
	allowVals   map[string]struct{}
}

var (
	activeMu sync.RWMutex
	active   *Config
)

// Use installs cfg for this process until the returned restore function runs.
// A nil cfg restores defaults. CLI Run always Reset()s at exit.
func Use(cfg *Config) func() {
	activeMu.Lock()
	prev := active
	active = cfg
	activeMu.Unlock()
	return func() {
		activeMu.Lock()
		active = prev
		activeMu.Unlock()
	}
}

// Reset restores default (no overlay) detection and display.
func Reset() {
	activeMu.Lock()
	active = nil
	activeMu.Unlock()
}

func current() *Config {
	activeMu.RLock()
	defer activeMu.RUnlock()
	return active
}

func currentDisplay() DisplayMode {
	c := current()
	if c == nil || c.Display == "" {
		return DisplayFingerprint
	}
	return c.Display
}

func (c *Config) allowKey(key string) bool {
	if c == nil || len(c.allowKeys) == 0 {
		return false
	}
	_, ok := c.allowKeys[NormalizeKey(key)]
	return ok
}

func (c *Config) allowVal(value string) bool {
	if c == nil || len(c.allowVals) == 0 {
		return false
	}
	_, ok := c.allowVals[value]
	return ok
}

func (c *Config) extraKey(key string) bool {
	if c == nil {
		return false
	}
	u := NormalizeKey(key)
	for _, re := range c.extraKeys {
		if re.MatchString(u) {
			return true
		}
	}
	return false
}

func (c *Config) extraVal(value string) bool {
	if c == nil {
		return false
	}
	for _, re := range c.extraValues {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

// Token returns the irreversible display for a withheld value: either the
// per-run HMAC fingerprint (default) or TokenRedacted. The HMAC key is never
// part of the token.
func (f *Fingerprinter) Token(value string) string {
	if currentDisplay() == DisplayRedacted {
		return TokenRedacted
	}
	if f == nil {
		return TokenRedacted
	}
	return f.Fingerprint(value)
}

// DisplayForSecret rewrites a stored fingerprint when the overlay asks for the
// withheld placeholder. Non-secret fingerprints are unchanged.
func DisplayForSecret(stored string, secret bool) string {
	if secret && currentDisplay() == DisplayRedacted {
		return TokenRedacted
	}
	return stored
}
