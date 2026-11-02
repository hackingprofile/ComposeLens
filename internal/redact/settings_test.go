// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestSettingsQualifiersAreWords(t *testing.T) {
	for _, qualifier := range []string{
		"TTL", "SECONDS", "MINUTES", "HOURS", "DAYS", "EXPIRY", "EXPIRES", "LENGTH",
		"MIN", "MAX", "COUNT", "LIMIT", "TIMEOUT", "INTERVAL", "BACKEND", "PROVIDER",
		"TYPE", "MODE", "POLICY", "ROTATION", "ENABLE", "ENABLED", "DISABLE", "DISABLED", "REQUIRED",
	} {
		for _, key := range []string{qualifier + "_PASSWORD", "TOKEN_" + qualifier} {
			if IsSecretKey(key) || MustRedactAt("services.api.environment."+key, "3600") {
				t.Errorf("setting classified as a credential: %s", key)
			}
			if !MustRedactAt("services.api.environment."+key, "https://admin:privatepass123@example.com") {
				t.Errorf("setting exposed embedded credentials: %s", key)
			}
		}
	}
	for _, key := range []string{"DB_PASSWORD", "API_TOKEN", "SECRET", "PASSWORD_FILE", "FIRST_PASSWORD", "REQUIREDNESS_PASSWORD", "TOKEN_MODEL", "TOKEN_TTL_VALUE"} {
		if !IsSecretKey(key) {
			t.Errorf("credential key missed: %s", key)
		}
	}
}

func TestBooleanSettingKeys(t *testing.T) {
	for _, key := range []string{"AUTH_ENABLED", "FIRST_PASS"} {
		if IsSecretKey(key) || MustRedact(key, "on") {
			t.Errorf("boolean setting hidden: %s", key)
		}
		if !MustRedact(key, "https://admin:privatepass123@example.com") {
			t.Errorf("credential value exposed under setting: %s", key)
		}
	}
}
