// SPDX-License-Identifier: Apache-2.0

package engineadapter

import (
	"strings"
	"testing"
)

func TestEngineOutputWithholdsValuesUnderSecretNamedMappings(t *testing.T) {
	raw := "name: demo\n" +
		"services:\n" +
		"  api:\n" +
		"    image: nginx\n" +
		"    x-auth:\n" +
		"      password:\n" +
		"        current: nestedleak789012\n" +
		"x-credentials:\n" +
		"  api_token:\n" +
		"    value: nestedleak123456\n" +
		"secrets:\n" +
		"  db_password:\n" +
		"    file: /run/db_password.txt\n"
	out, _ := RedactEngineOutput(raw)
	for _, s := range []string{"nestedleak789012", "nestedleak123456"} {
		if strings.Contains(out, s) {
			t.Errorf("engine output kept %q:\n%s", s, out)
		}
	}
	for _, keep := range []string{"nginx", "/run/db_password.txt", "name: demo"} {
		if !strings.Contains(out, keep) {
			t.Errorf("engine output lost ordinary value %q:\n%s", keep, out)
		}
	}
}

func TestEngineOutputWithholdsArgvValueAfterSecretFlag(t *testing.T) {
	raw := "services:\n  api:\n    command:\n      - --token\n      - nextargtoken666\n      - --verbose\n    image: nginx\n"
	out, _ := RedactEngineOutput(raw)
	if strings.Contains(out, "nextargtoken666") {
		t.Errorf("engine output kept the argv secret:\n%s", out)
	}
	if !strings.Contains(out, "--verbose") || !strings.Contains(out, "--token") {
		t.Errorf("engine output lost ordinary argv:\n%s", out)
	}
}
