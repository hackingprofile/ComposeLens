// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const detectSecret = "solar-secretvalue-20261003"

func detectToken() string { return "ghp_" + strings.Repeat("a", 30) }

// Only text matching the version grammar is kept as a version.
func TestVersionGrammar(t *testing.T) {
	for _, ok := range []string{"2.29.7", "v5.4.0", "v2.29.7-desktop.1", "1.29.2", "2.40.3+build.7"} {
		if !ValidVersion(ok) {
			t.Errorf("%q rejected", ok)
		}
	}
	for _, bad := range []string{"", detectToken(), "Docker Compose version " + detectToken(), "2.29.7 " + detectToken(), "v5", "x" + strings.Repeat("1", 200), "2.29.7\n" + detectToken()} {
		if ValidVersion(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if got := parseVersion("Docker Compose version " + detectToken() + "\n"); got != "" {
		t.Errorf("token parsed as version: %q", got)
	}
}

// Version text and failing-detection detail are validated, redacted
// and bounded before they are stored, on the plugin and standalone paths.
func TestDetectWithholdsSecretMetadataOnBothPaths(t *testing.T) {
	tok := detectToken()
	failing := errors.New("docker config error password=" + detectSecret + " " + tok)
	cases := map[string]Detector{
		"plugin version is a token": {Run: func(_ context.Context, name string, _ ...string) (string, error) {
			return tok + "\n", nil
		}},
		"standalone version is a token": {Run: func(_ context.Context, name string, _ ...string) (string, error) {
			if name == "docker" {
				return "", errors.New("not found")
			}
			return "docker-compose version " + tok + "\n", nil
		}},
		"plugin and standalone fail with secret detail": {Run: func(context.Context, string, ...string) (string, error) {
			return "", failing
		}, LookPath: func(string) (string, error) { return "found", nil }},
		"plugin fails with secret, standalone missing": {Run: func(_ context.Context, name string, _ ...string) (string, error) {
			if name == "docker" {
				return "", failing
			}
			return "", errors.New(`exec: "docker-compose": executable file not found in %PATH%`)
		}, LookPath: func(file string) (string, error) {
			if file == "docker" {
				return "found", nil
			}
			return "", errors.New("not found")
		}},
	}
	for name, d := range cases {
		info := d.Detect()
		raw, _ := json.Marshal(info)
		for _, s := range []string{tok, detectSecret} {
			if strings.Contains(string(raw), s) {
				t.Errorf("%s: %q stored in %s", name, s, raw)
			}
		}
		if info.State == "known" {
			t.Errorf("%s: token accepted as a version: %+v", name, info)
		}
		if len(info.Detail) > MaxDetailBytes {
			t.Errorf("%s: detail not bounded (%d bytes)", name, len(info.Detail))
		}
	}
	// The withheld fragments are guard material for every output that carries Info.
	info := cases["plugin fails with secret, standalone missing"].Detect()
	material := strings.Join(info.GuardMaterial(), "\n")
	if !strings.Contains(material, detectSecret) {
		t.Errorf("withheld detection secret is not guard material: %q", material)
	}
}
