// SPDX-License-Identifier: Apache-2.0

package cli

import "testing"

func TestCredentialWordsAndArgumentFormsAreWithheld(t *testing.T) {
	compose := `services:
  api:
    image: nginx
    environment:
      SMTP_PASS_PROD: shapeleak31
      DSN_PRIMARY: shapeleak32
      dbPwd: shapeleak33
      mysqlPw: shapeleak34
      REDIS_AUTH: shapeleak35
      NPM_AUTH: shapeleak36
      UPSTREAM: LettersOnlyTokenQwErTyUiOpAsDfGhJkLzXcVbNmQwErTy
      SHORT_ALNUM: a1b2c3d4e5f6a7b8c9d0e1f2a3b
      CURL_OPTS: "-u admin:shapeleak39 --silent"
      USER_OPTS: "--user admin:shapeleak40 --silent"
      DB_OPTS: "mysql -u admin -p shapeleak41"
    command: ["-p", "shapeleak46", "--auth", "shapeleak48", "-u", "admin:shapeleak49"]
`
	dir := writeProject(t, map[string]string{"compose.yaml": compose})
	assertNoneLeak(t, dir, []string{
		"shapeleak31", "shapeleak32", "shapeleak33", "shapeleak34", "shapeleak35", "shapeleak36",
		"LettersOnlyTokenQwErTyUiOpAsDfGhJkLzXcVbNmQwErTy", "a1b2c3d4e5f6a7b8c9d0e1f2a3b",
		"shapeleak39", "shapeleak40", "shapeleak41", "shapeleak46", "shapeleak48", "shapeleak49",
	})
}
