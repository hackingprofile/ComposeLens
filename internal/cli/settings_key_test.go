// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestSettingValues(t *testing.T) {
	for _, tc := range []struct{ key, value string }{
		{"TOKEN_TTL_SECONDS", "3600"},
		{"PASSWORD_MIN_LENGTH", "12"},
		{"SECRET_BACKEND", "vault"},
		{"TOKEN_EXPIRY", "1h"},
		{"ENABLE_PASSWORD_RESET", "true"},
		{"API_KEY_HEADER", "X-Key"},
		{"SECRETS_DIR", "/run"},
		{"TOKEN_ISSUER", "local"},
	} {
		t.Run(tc.key, func(t *testing.T) {
			dir := writeProject(t, map[string]string{"compose.yaml": "services:\n  api:\n    image: nginx\n    environment:\n      " + tc.key + ": \"" + tc.value + "\"\n"})
			for _, args := range [][]string{{"inspect"}, {"inspect", "--json"}, {"explain", "--all"}, {"explain", "api:" + tc.key}, {"check"}, {"report", "--json", "--no-engine"}, {"report", "--html", "--no-engine"}} {
				code, out, err := runIn(t, dir, nil, args...)
				if code != 0 {
					t.Errorf("%v exit=%d: %s %s", args, code, out, err)
				}
				if args[0] == "inspect" && len(args) == 1 && !strings.Contains(out, "value="+tc.value) {
					t.Errorf("setting value hidden: %s", out)
				}
			}
		})
	}
}

func TestSettingCredentials(t *testing.T) {
	for _, tc := range []struct {
		key, value string
		exit       int
	}{
		{"DB_PASSWORD", "1234", 4},
		{"API_TOKEN", "abc", 4},
		{"SECRET", "x", 4},
		{"PASSWORD_FILE", "/run/db.txt", 0},
		{"TOKEN_TTL_SECONDS", "ghp_" + strings.Repeat("aB3c", 10), 0},
		{"ENABLE_PASSWORD_RESET", "https://admin:privatepass123@example.com", 0},
	} {
		t.Run(tc.key+tc.value[:1], func(t *testing.T) {
			dir := writeProject(t, map[string]string{"compose.yaml": "services:\n  api:\n    image: nginx\n    environment:\n      " + tc.key + ": \"" + tc.value + "\"\n"})
			for _, args := range [][]string{{"inspect"}, {"explain", "--all"}, {"report", "--json", "--no-engine"}, {"report", "--html", "--no-engine"}, {"check"}} {
				code, out, err := runIn(t, dir, nil, args...)
				if code != tc.exit || strings.Contains(out+err, tc.value) {
					t.Errorf("%v exit=%d want %d, value exposed=%t", args, code, tc.exit, strings.Contains(out+err, tc.value))
				}
			}
		})
	}
}

func TestSettingBooleans(t *testing.T) {
	for _, tc := range []struct{ key, value string }{{"AUTH_ENABLED", "true"}, {"FIRST_PASS", "on"}} {
		t.Run(tc.key, func(t *testing.T) {
			dir := writeProject(t, map[string]string{"compose.yaml": "services:\n  api:\n    image: nginx\n    environment:\n      " + tc.key + ": \"" + tc.value + "\"\n"})
			code, out, err := runIn(t, dir, nil, "inspect")
			if code != 0 || !strings.Contains(out, "value="+tc.value) {
				t.Fatalf("boolean hidden or refused: exit=%d %s %s", code, out, err)
			}
			code, out, err = runIn(t, dir, nil, "explain", "api:"+tc.key)
			if code != 0 || !strings.Contains(out, "effective: "+tc.value) {
				t.Fatalf("boolean explanation hidden or refused: exit=%d %s %s", code, out, err)
			}
		})
	}
}
