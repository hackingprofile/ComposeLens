// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestIsComposeIdentity(t *testing.T) {
	yes := []string{
		"services.my-application-service-v2.image",
		"services.payment-gateway-worker-01.environment.FOO",
		"my-application-service-v2:API_TOKEN",
		"payment-gateway-worker-01:COLOR",
		"services.web",
	}
	for _, s := range yes {
		if !IsComposeIdentity(s) {
			t.Fatalf("want identity: %q", s)
		}
	}
	no := []string{
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"AKIAIOSFODNN7EXAMPLE",
		"postgres://demo-user:synthetic-password@db.internal/app",
		`C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\compose.yaml`,
		"winner:environment:C:\\Users\\x\\compose.yaml",
		"alpine",
		"",
	}
	for _, s := range no {
		if IsComposeIdentity(s) {
			t.Fatalf("not an identity: %q", s)
		}
	}
}

func TestDisplayHumanIdentityNotRedactedValueStillRedacted(t *testing.T) {
	id := "services.my-application-service-v2.image"
	if DisplayHuman(id) != id {
		t.Fatalf("identity redacted: %q", DisplayHuman(id))
	}
	env := "payment-gateway-worker-01:API_TOKEN"
	if DisplayHuman(env) != env {
		t.Fatalf("env identity redacted: %q", DisplayHuman(env))
	}
	secret := "ghp_abcdefghijklmnopqrstuvwxyz0123456789"
	if DisplayHuman(secret) != TokenRedacted {
		t.Fatalf("secret value not redacted: %q", DisplayHuman(secret))
	}
	path := `C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\compose.yaml`
	if DisplayHuman(path) != path {
		t.Fatalf("filesystem path should stay visible: %q", DisplayHuman(path))
	}
}
