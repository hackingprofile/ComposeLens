// SPDX-License-Identifier: Apache-2.0

package redact

import "testing"

func TestCredentialWordsAtEveryKeyPosition(t *testing.T) {
	for _, key := range []string{"SMTP_PASS_PROD", "DSN_PRIMARY", "dbPwd", "mysqlPw", "REDIS_AUTH", "NPM_AUTH"} {
		if !IsSecretKey(key) {
			t.Errorf("credential key missed: %s", key)
		}
	}
}

func TestCredentialRunsAndOrdinaryArguments(t *testing.T) {
	for _, value := range []string{"LettersOnlyTokenQwErTyUiOpAsDfGhJkLzXcVbNmQwErTy", "a1b2c3d4e5f6a7b8c9d0e1f2a3b", "mysql -p shapeleak41", "curl -u admin:shapeleak39", "--auth shapeleak48"} {
		if !LooksLikeSecret(value) {
			t.Errorf("credential value missed: %s", value)
		}
	}
	for _, value := range []string{"--port 8080", "-p 8080", "curl --user admin", "SIGTERM", "service_started", "BuildCache2026", "the application serves ordinary requests", "ThisIsAnOrdinaryDescriptiveConfigurationName"} {
		if LooksLikeSecret(value) {
			t.Errorf("ordinary value withheld: %s", value)
		}
	}
}
