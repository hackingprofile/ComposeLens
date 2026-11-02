// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"bytes"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestIsSecretKey(t *testing.T) {
	secrets := []string{
		"API_TOKEN", "password", "DB_PASSWORD", "AWS_SECRET_ACCESS_KEY", "PRIVATE_KEY", "GPG_KEY", "api-key",
		"access_token", "refresh_token", "auth_token", "id_token", "client_secret", "access_key", "secret_key",
		"passwd", "pwd", "passphrase", "PWD", "access-token",
	}
	for _, k := range secrets {
		if !IsSecretKey(k) {
			t.Fatalf("expected secret key %q", k)
		}
	}
	safe := []string{"APP_ENV", "LOG_LEVEL", "DATABASE_URL", "COMPOSE_FILE", "HOSTNAME", "WEB_IMAGE", "DOCKER_HOST", "page", "sort", "PAGE_URL"}
	for _, k := range safe {
		if IsSecretKey(k) {
			t.Fatalf("did not expect secret key %q", k)
		}
	}
}

func TestLooksLikeSecret(t *testing.T) {
	if !LooksLikeSecret("AKIAIOSFODNN7EXAMPLE") {
		t.Fatal("AWS-shaped value")
	}
	if !LooksLikeSecret("ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatal("github token")
	}
	if LooksLikeSecret("postgres://localhost:5432/app") {
		t.Fatal("ordinary URL should not trip probable-secret")
	}
	if !LooksLikeSecret("tcp://demo-user:synthetic-password@internal-host/socket") {
		t.Fatal("DOCKER_HOST-shaped URI with password")
	}
	if !LooksLikeSecret("postgres://demo-user:synthetic-password@db.internal/app") {
		t.Fatal("credential DSN")
	}
	if !LooksLikeSecret("https://api.example.invalid/hook?token=synthetic-token-value") {
		t.Fatal("token query")
	}
	querySecrets := []string{
		"https://api.example.invalid/hook?access_token=synthetic-access-token-value",
		"https://api.example.invalid/hook?refresh_token=synthetic-refresh-token-value",
		"https://api.example.invalid/hook?auth_token=synthetic-auth-token-value",
		"https://api.example.invalid/hook?client_secret=synthetic-client-secret-value",
		"https://api.example.invalid/hook?pwd=synthetic-pwd-value",
		"https://api.example.invalid/hook?access-token=synthetic-hyphen-token-value",
		"https://api.example.invalid/hook?id_token=synthetic-id-token-value",
		"https://api.example.invalid/hook?access_key=synthetic-access-key-value",
		"https://api.example.invalid/hook?secret_key=synthetic-secret-key-value",
		"https://api.example.invalid/hook?private_key=synthetic-private-key-value",
		"https://api.example.invalid/hook?api_key=synthetic-api-key-value",
		"https://api.example.invalid/hook?password=synthetic-password-query-value",
		"https://api.example.invalid/hook?passwd=synthetic-passwd-value",
		"https://api.example.invalid/hook?passphrase=synthetic-passphrase-value",
	}
	for _, u := range querySecrets {
		if !LooksLikeSecret(u) {
			t.Fatalf("expected secret query URL %s", u)
		}
		frags := SecretFragments(u)
		found := false
		for _, f := range frags {
			if strings.Contains(f, "synthetic-") {
				found = true
			}
		}
		if !found {
			t.Fatalf("SecretFragments missed query value in %s: %v", u, frags)
		}
	}
	if LooksLikeSecret("https://api.example.invalid/items?page=2&sort=name") {
		t.Fatal("pagination query should remain visible")
	}
	if LooksLikeSecret("https://api.example.invalid/items/catalog/v1") {
		t.Fatal("credential-free URL should remain visible")
	}
}

func TestLooksLikeSecretInterpolationSyntaxNotHighEntropy(t *testing.T) {
	benign := "alpine:${CL_PROBE_TAG:-3.21.3}"
	if LooksLikeSecret(benign) {
		t.Fatalf("benign interpolation classified as secret: %q", benign)
	}
	if stripComposeInterpolation(benign) != "alpine:" {
		t.Fatalf("strip=%q", stripComposeInterpolation(benign))
	}
	if LooksLikeSecret("alpine:${TAG-3.21.3}") || LooksLikeSecret("nginx:$TAG") || LooksLikeSecret("$$VAR") {
		t.Fatal("ordinary interpolation forms classified as secrets")
	}
	secretDefault := "alpine:${UNSET:-ghp_abcdefghijklmnopqrstuvwxyz0123456789}"
	if !LooksLikeSecret(secretDefault) {
		t.Fatal("known secret pattern inside interpolation default must still match")
	}
	if !LooksLikeSecret("ghp_abcdefghijklmnopqrstuvwxyz0123456789") {
		t.Fatal("github token")
	}
	if !LooksLikeSecret("aB3$xY9#mK2pQ7nx5wR8tV1cZ4jH6uD0") {
		t.Fatal("high-entropy token without interpolation must still match")
	}
}

func TestLooksLikeSecretFilesystemPathsNotHighEntropy(t *testing.T) {
	paths := []string{
		`C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\compose.yaml`,
		`C:\Users\x\AppData\Local\Temp\composelens-hclass-repro99\extra.env`,
		`winner:environment:C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\compose.yaml`,
		`loser:env-file:C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\extra.env`,
		`project-env:C:\Users\x\AppData\Local\Temp\abcdefghijklmnop1234567890\.env`,
		`/tmp/composelens-hclass-repro99/compose.yaml`,
		`./fixtures/graph/shadow-chain/compose.yml`,
	}
	for _, p := range paths {
		if LooksLikeSecret(p) {
			t.Fatalf("filesystem path classified as secret: %q", p)
		}
	}
}

func TestLooksLikeSecretBatteryUnchanged(t *testing.T) {
	secrets := []string{
		"API_TOKEN_VALUE_PLACEHOLDER", // content via high-entropy below
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_abcdefghijklmnopqrstuvwxyz0123456789",
		"github_pat_abcdefghijklmnopqrstuvwxyz0123456789",
		"xox" + "b-12345678901-abcdefghijklmnopqrstuv", // joined at run time so the source holds no token-shaped literal
		"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abc",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5J\n-----END RSA PRIVATE KEY-----",
		"https://api.example.invalid/hook?access_token=synthetic-access-token-value",
		"https://demo-user:synthetic-password@internal-host/socket",
		"aB3$xY9#mK2pQ7nx5wR8tV1cZ4jH6uD0",
		`C:\tmp\ghp_abcdefghijklmnopqrstuvwxyz0123456789\compose.yaml`,
		`C:\tmp\AKIAIOSFODNN7EXAMPLE\compose.yaml`,
		`winner:environment:C:\tmp\ghp_abcdefghijklmnopqrstuvwxyz0123456789\app.yaml`,
	}
	if !IsSecretKey("API_TOKEN") || !IsSecretKey("PASSWORD") || !IsSecretKey("SECRET") || !IsSecretKey("API_KEY") {
		t.Fatal("key-based detection weakened")
	}
	if !LooksLikeSecret("aB3$xY9#mK2pQ7nx5wR8tV1cZ4jH6uD0") {
		t.Fatal("high-entropy non-path token must still redact")
	}
	for _, s := range secrets {
		if s == "API_TOKEN_VALUE_PLACEHOLDER" {
			continue
		}
		if !LooksLikeSecret(s) {
			t.Fatalf("secret detection weakened for %q", s)
		}
	}
}

func TestFingerprinterSameRunAndCrossRun(t *testing.T) {
	a, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	same := a.Fingerprint("same")
	if same != a.Fingerprint("same") {
		t.Fatal("same key + same value must match inside one run")
	}
	if a.Fingerprint("same") == a.Fingerprint("other") {
		t.Fatal("same key + different value must differ")
	}
	if a.Fingerprint("same") == b.Fingerprint("same") {
		t.Fatal("independent run keys must not link the same value")
	}
	if !stringsHasPrefix(same, "hmac-sha256:") {
		t.Fatalf("unexpected fingerprint %s", same)
	}
}

func TestFingerprinterRandomFailure(t *testing.T) {
	_, err := NewFingerprinterFrom(failReader{})
	if err == nil {
		t.Fatal("expected fail-closed")
	}
	if _, err := NewFingerprinterFrom(nil); err == nil {
		t.Fatal("nil reader")
	}
}

func TestFingerprinterKeyNotInFingerprint(t *testing.T) {
	fp, err := NewFingerprinter()
	if err != nil {
		t.Fatal(err)
	}
	out := fp.Fingerprint("value")
	for _, g := range fp.GuardMaterial() {
		if g != "" && bytes.Contains([]byte(out), []byte(g)) {
			t.Fatal("key material appeared in fingerprint")
		}
	}
}

type failReader struct{}

func (failReader) Read([]byte) (int, error) { return 0, errors.New("no entropy") }

func stringsHasPrefix(s, p string) bool {
	return len(s) >= len(p) && s[:len(p)] == p
}

func TestFlagNameAndDiagnosticRedaction(t *testing.T) {
	if got := FlagName("--password=synthetic-cli-password"); got != "--password" {
		t.Fatalf("FlagName=%s", got)
	}
	if DiagnosticLabel("synthetic-cli-password") != "<redacted>" {
		t.Fatal("password-shaped argument should hide")
	}
	if DiagnosticLabel("https://demo-user:synthetic-password@internal-host/socket") != "<redacted>" {
		t.Fatal("credential URL should hide")
	}
	if DiagnosticLabel("missing.yaml") != "missing.yaml" {
		t.Fatal("safe path should remain visible")
	}
	longSafe := `C:\Users\x\AppData\Local\Temp\TestEarlyErrorsDoNotEchoSecrets001\missing.yaml`
	if ShouldHideDiagnostic(longSafe) {
		t.Fatal("long safe filesystem path must not hide")
	}
	if DiagnosticLabel(longSafe) != longSafe {
		t.Fatal("long safe path label")
	}
	if !ShouldHideDiagnostic(`C:\tmp\synthetic-cli-password.env`) {
		t.Fatal("secret-shaped filename must hide")
	}
	quoted := `C:\tmp\synthetic-cli-password.env`
	err := errors.New(`env-file "` + strings.ReplaceAll(quoted, `\`, `\\`) + `": CreateFile ` + quoted + `: missing`)
	got := RedactInError(err, quoted)
	if got == nil || strings.Contains(got.Error(), "synthetic-cli-password") {
		t.Fatalf("quoted Windows path leaked: %v", got)
	}
	safeErr := errors.New(`file "C:\tmp\missing.yaml": missing`)
	if RedactInError(safeErr, `C:\tmp\missing.yaml`).Error() != safeErr.Error() {
		t.Fatal("safe path must not be rewritten")
	}
}

var _ io.Reader = failReader{}
