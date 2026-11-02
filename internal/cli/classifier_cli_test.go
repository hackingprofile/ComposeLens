// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

const classifierCompose = `services:
  api:
    image: nginx
    environment:
      DB_PASS: hunter2xyz
      MYSQL_ROOT_PASS: s3cr3tvalue
      PGPASS: plainvalue99
      STRIPE_SK: 4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a
      SESSION_COOKIE_SIGNING: Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg
      JAVA_OPTS: "-Xmx1g -Djavax.net.ssl.keyStorePassword=keystorepw999"
      BLOB_URL: "https://acct.blob.core.windows.net/c/f?sv=2022-11-02&sig=sasSignatureValue123%2Bxyz"
      STOP_MODE: graceful
    stop_signal: SIGTERM
    healthcheck:
      test: ["CMD", "curl", "-H", "Authorization: Bearer bearertokenvalue42", "http://localhost"]
    command: ["--password=cmdflagpw555", "--token", "nextargtoken666", "--verbose"]
`

var classifierSecrets = []string{
	"hunter2xyz", "s3cr3tvalue", "plainvalue99", "4f9a8c2e7b1d", "Zm9vYmFy",
	"keystorepw999", "sasSignatureValue", "bearertokenvalue42", "cmdflagpw555", "nextargtoken666",
}

func TestClassifierCatchesCommonSecretForms(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": classifierCompose})
	assertNoneLeak(t, dir, classifierSecrets)
	_, out, _ := runIn(t, dir, nil, "inspect")
	for _, keep := range []string{"value=graceful", "value=SIGTERM", "value=--verbose", "value=nginx"} {
		if !strings.Contains(out, keep) {
			t.Errorf("ordinary value %q hidden:\n%s", keep, out)
		}
	}
}

func TestClassifierCatchesSecretFormsInsideOneCommandString(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": "services:\n  api:\n    image: nginx\n" +
		"    command: \"serve --token nextargtoken666 --api-key=flagkey777777 --port 8080\"\n"})
	assertNoneLeak(t, dir, []string{"nextargtoken666", "flagkey777777"})
}
