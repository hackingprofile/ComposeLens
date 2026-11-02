// SPDX-License-Identifier: Apache-2.0

package redact

import "strings"

// settingWords qualify a key as a configuration option when they are its
// first or last word. Value-shape checks still apply independently.
var settingWords = map[string]struct{}{
	"TTL": {}, "SECONDS": {}, "MINUTES": {}, "HOURS": {}, "DAYS": {},
	"EXPIRY": {}, "EXPIRES": {}, "LENGTH": {}, "MIN": {}, "MAX": {},
	"COUNT": {}, "LIMIT": {}, "TIMEOUT": {}, "INTERVAL": {},
	"BACKEND": {}, "PROVIDER": {}, "TYPE": {}, "MODE": {}, "POLICY": {},
	"ROTATION": {}, "ENABLE": {}, "ENABLED": {}, "DISABLE": {},
	"DISABLED": {}, "REQUIRED": {}, "HEADER": {}, "DIR": {}, "PATH": {},
	"ISSUER": {}, "AUDIENCE": {}, "ALGORITHM": {}, "FORMAT": {}, "PREFIX": {},
}

func settingKey(normalized string) bool {
	words := strings.FieldsFunc(normalized, func(r rune) bool { return r == '_' || r == '.' })
	if len(words) < 2 {
		return false
	}
	_, prefix := settingWords[words[0]]
	_, suffix := settingWords[words[len(words)-1]]
	return prefix || suffix
}
