// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

func TestResourceNamesAndShortOptionsDoNotRefuse(t *testing.T) {
	cases := []string{
		"services: {api: {image: nginx, depends_on: {password-reset: {condition: service_started, restart: true}}}, password-reset: {image: busybox}}",
		"services: {api: {image: nginx, depends_on: {secrets-manager: {required: false}}}, secrets-manager: {image: busybox}}",
		"services: {api: {image: nginx, networks: {token-net: {priority: 10}}}}\nnetworks: {token-net: {driver: bridge}}",
		"services: {password-reset: {image: nginx, environment: {FIRST_PASS: 'on', ENABLE_COOKIE: '1'}}}\nx-sig: {enabled: true}",
		"services: {api: {image: nginx}}\nvolumes: {password-store: {external: true}}\nconfigs: {token-config: {external: true}}\nsecrets: {private-token: {external: true}}",
	}
	for i, compose := range cases {
		dir := writeProject(t, map[string]string{"compose.yaml": compose + "\n"})
		for _, args := range outputCommands {
			code, out, errs := runIn(t, dir, nil, args...)
			if code != 0 && code != 6 {
				t.Errorf("case %d %v: code=%d stderr=%s", i, args, code, errs)
			}
			if code == 0 && out == "" {
				t.Errorf("case %d %v: empty output", i, args)
			}
		}
	}
}

func TestOrdinaryIdentifiersRemainVisible(t *testing.T) {
	values := []string{
		"4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a",
		"registry/app:4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a",
		"SIGTERM", "service_started",
		"registry/app@sha256:4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a4f9a8c2e7b1d6f3a0c5e8b2d",
		"550e8400-e29b-41d4-a716-446655440000",
	}
	compose := "services:\n  api:\n    image: nginx\n    environment:\n      GIT_COMMIT: " + values[0] + "\n      BUILD_IMAGE: " + values[1] + "\n      KILL_SIG: SIGTERM\n      IMAGE_DIGEST: " + values[4] + "\n      REQUEST_ID: " + values[5] + "\n    depends_on:\n      auth-token-svc: {condition: service_started}\n  auth-token-svc: {image: busybox}\n"
	dir := writeProject(t, map[string]string{"compose.yaml": compose})
	for _, args := range [][]string{{"inspect"}, {"inspect", "--json"}, {"report", "--json", "--no-engine"}} {
		code, out, errs := runIn(t, dir, nil, args...)
		if code != 0 {
			t.Fatalf("%v: code=%d stderr=%s", args, code, errs)
		}
		for _, value := range values {
			if !strings.Contains(out, value) {
				t.Errorf("%v: ordinary value withheld: %s", args, value)
			}
		}
	}
}
