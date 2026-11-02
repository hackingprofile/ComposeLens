// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestSecretPathChecksEveryMappingKey(t *testing.T) {
	secret := []string{
		"x-credentials.api_token.value",
		"services.api.x-auth.password.current",
		"services.api.environment.DB_PASSWORD",
		"services.api.x-vault.client_secret.v[0]",
		"x-cfg.private_key.pem.body",
		"services.api.labels.com.example.token",
	}
	for _, p := range secret {
		if !SecretPath(p) {
			t.Errorf("SecretPath(%q) = false, want true", p)
		}
		if !MustRedactAt(p, "plainvalue") {
			t.Errorf("MustRedactAt(%q, plain) = false, want true", p)
		}
	}
	plain := []string{
		"services.api.image",
		"services.token-service.image",
		"services.api.secrets[0].source",
		"services.api.build.secrets[0]",
		"secrets.db_password.file",
		"secrets.api_token.environment",
		"configs.app_secret.file",
		"networks.secretnet.driver",
		"volumes.keys.driver",
		"services.api.healthcheck.test[1]",
		"",
	}
	for _, p := range plain {
		if SecretPath(p) {
			t.Errorf("SecretPath(%q) = true, want false", p)
		}
	}
}

func TestRawReferenceShowableOnlyForPlainReferences(t *testing.T) {
	if !RawReferenceShowable("services.api.command", "mysql -uroot -p${DB_PASSWORD}") {
		t.Error("a plain reference in a neutral field should be showable")
	}
	if !RawReferenceShowable("services.api.command", "mysql -p$DB_PASSWORD --cost=$$5") {
		t.Error("$NAME and an escaped $$ should be showable")
	}
	for _, raw := range []string{
		"alpine:${API_TOKEN:-sample-credential-value-7319}",
		"${A:+literalalt}",
		"${A?message}",
		"plain text",
	} {
		if RawReferenceShowable("services.web.image", raw) {
			t.Errorf("RawReferenceShowable(%q) = true, want false", raw)
		}
	}
	if RawReferenceShowable("services.api.environment.DB_PASSWORD", "${DB_PASSWORD}") {
		t.Error("a raw form under a secret path must stay withheld")
	}
}
