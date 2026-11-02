// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

const longDBPassword = "LongEnoughSecret1"

func TestInterpolatedSecretInPlainFieldsIsWithheldNotRefused(t *testing.T) {
	env := "DB_PASSWORD=" + longDBPassword + "\n"
	cases := map[string]string{
		"command": "services:\n  api:\n    image: nginx\n    command: \"mysql -uroot -p${DB_PASSWORD}\"\n",
		"healthcheck": "services:\n  api:\n    image: nginx\n    healthcheck:\n" +
			"      test: [\"CMD\", \"mysqladmin\", \"ping\", \"-p${DB_PASSWORD}\"]\n",
		"build-args": "services:\n  api:\n    image: nginx\n    build:\n      context: .\n" +
			"      args:\n        CONN: \"user:${DB_PASSWORD}@db\"\n",
		"extension": "x-conn: \"pw ${DB_PASSWORD}\"\nservices:\n  api:\n    image: nginx\n",
		"extended":  "services:\n  api:\n    extends: {file: base.yaml, service: b}\n",
	}
	for name, compose := range cases {
		t.Run(name, func(t *testing.T) {
			files := map[string]string{".env": env, "compose.yaml": compose}
			if name == "extended" {
				files["base.yaml"] = "services:\n  b:\n    image: nginx\n    command: \"mysql -p${DB_PASSWORD}\"\n"
			}
			dir := writeProject(t, files)
			assertNoneLeak(t, dir, []string{longDBPassword})
		})
	}
}

func TestInterpolatedSecretKeepsRawReferenceVisible(t *testing.T) {
	dir := writeProject(t, map[string]string{
		".env":         "DB_PASSWORD=" + longDBPassword + "\n",
		"compose.yaml": "services:\n  api:\n    image: nginx\n    command: \"mysql -uroot -p${DB_PASSWORD}\"\n",
	})
	_, out, _ := runIn(t, dir, nil, "inspect")
	if !strings.Contains(out, "mysql -uroot -p${DB_PASSWORD}") {
		t.Errorf("the raw form showing where the secret is interpolated should stay visible:\n%s", out)
	}
}

func TestAliasOfSecretValueIsWithheldNotRefused(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "x-s: &s aliasedsecretvalue77\n" +
			"services:\n  w:\n    image: nginx\n    environment:\n      DB_PASSWORD: *s\n",
	})
	assertNoneLeak(t, dir, []string{"aliasedsecretvalue77"})
}
