// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestSecretKeyTokens(t *testing.T) {
	for _, k := range []string{
		"DB_PASS", "MYSQL_ROOT_PASS", "PGPASS", "DB_PW", "URL_SIG", "SESSION_COOKIE_SIGNING",
		"RABBITMQ_ERLANG_COOKIE", "SENTRY_DSN", "PASSWORD_SALT", "WEBHOOK_SIGNATURE", "sig", "pass",
	} {
		if !IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = false, want true", k)
		}
	}
	for _, k := range []string{
		"STOP_SIGNAL", "stop_signal", "BYPASS_CACHE", "COMPASS_URL", "COOKIE_SECURE", "COOKIE_DOMAIN",
		"PASS_THROUGH_MODE", "DESIGN_MODE", "SIGNAL", "PATH", "image", "command", "DSN_TIMEOUT",
	} {
		if IsSecretKey(k) {
			t.Errorf("IsSecretKey(%q) = true, want false", k)
		}
	}
}

func TestSecretValueShapes(t *testing.T) {
	secret := []string{
		"4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a",
		"Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg",
		"-Xmx1g -Djavax.net.ssl.keyStorePassword=keystorepw999",
		"Authorization: Bearer bearertokenvalue42",
		"X-Api-Key: headerkeyvalue77",
		"--password=cmdflagpw555",
		"serve --token nextargtoken666 --port 8080",
		"https://acct.blob.core.windows.net/c/f?sv=2022-11-02&sig=sasSignatureValue123%2Bxyz",
	}
	for _, v := range secret {
		if !LooksLikeSecret(v) {
			t.Errorf("LooksLikeSecret(%q) = false, want true", v)
		}
	}
	plain := []string{
		"TestSecretUnderSecretNamedMappingInterpolatedIsWithheld380355528",
		"nginx -g 'daemon off;'",
		"-Xmx1g -Dspring.profiles.active=prod",
		"--port 8080 --verbose",
		"--token-file /run/secrets/token",
		"sh -c \"echo token expired\"",
		"Content-Type: application/json",
		"SIGTERM",
		"graceful",
		"postgres://localhost:5432/app",
		`D:\Projects\My Apps\composelens\fixtures\perf\large\compose.yaml`,
		"/home/runner/work/composelens/composelens/examples/readme-demo/compose.yaml",
	}
	for _, v := range plain {
		if LooksLikeSecret(v) {
			t.Errorf("LooksLikeSecret(%q) = true, want false", v)
		}
	}
}

func TestSecretFragmentsIncludeParts(t *testing.T) {
	cases := map[string]string{
		"-Xmx1g -Djavax.net.ssl.keyStorePassword=keystorepw999": "keystorepw999",
		"Authorization: Bearer bearertokenvalue42":              "bearertokenvalue42",
		"serve --token nextargtoken666 --port 8080":             "nextargtoken666",
		"--password=cmdflagpw555":                               "cmdflagpw555",
	}
	for v, want := range cases {
		found := false
		for _, f := range SecretFragments(v) {
			if f == want {
				found = true
			}
		}
		if !found {
			t.Errorf("SecretFragments(%q) lacks %q: %v", v, want, SecretFragments(v))
		}
	}
}

func TestArgvSecretFollowsFlag(t *testing.T) {
	if !SecretFlag("--token") || !SecretFlag("-password") || !SecretFlag("--api-key") {
		t.Error("secret-named flags not recognized")
	}
	if SecretFlag("--token=x") || SecretFlag("--verbose") || SecretFlag("token") || SecretFlag("--token-file") {
		t.Error("non-flag or non-secret flag recognized as secret flag")
	}
}
