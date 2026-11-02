// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"composelens/internal/exitcode"
)

// Repeated, semicolon-joined and malformed credential queries, and a
// second DSN password, never print the credential.
func TestCredentialQueriesAndDSNsNeverPrint(t *testing.T) {
	cases := []struct {
		name, env, secret string
		args              []string
	}{
		{"query-empty-first", "ENDPOINT: \"https://example.test/?api_key=&api_key=solar-secretvalue\"", "solar-secretvalue", []string{"inspect", "--json"}},
		{"query-empty-first-report", "ENDPOINT: \"https://example.test/?api_key=&api_key=solar-secretvalue\"", "solar-secretvalue", []string{"report", "--json"}},
		{"query-semicolon", "ENDPOINT: \"https://example.test/?password=solar-secretvalue;mode=rw\"", "solar-secretvalue", []string{"inspect", "--json"}},
		{"query-invalid-escape", "ENDPOINT: \"https://example.test/?password=solar-secretvalue%zz\"", "solar-secretvalue", []string{"inspect", "--json"}},
		{"query-second-copy", "PASSWORD: \"https://example.test/?api_key=solar-firstsecretvalue&api_key=solar-secondsecretvalue\"\n      COPY: \"solar-secondsecretvalue\"", "solar-secondsecretvalue", []string{"explain", "web:COPY"}},
		{"dsn-second-copy", "PASSWORD: \"server=example.test;password=solar-firstsecretvalue;password=solar-secondsecretvalue\"\n      COPY: \"solar-secondsecretvalue\"", "solar-secondsecretvalue", []string{"explain", "web:COPY"}},
		{"dsn-second-copy-json", "PASSWORD: \"server=example.test;password=solar-firstsecretvalue;password=solar-secondsecretvalue\"\n      COPY: \"solar-secondsecretvalue\"", "solar-secondsecretvalue", []string{"explain", "web:COPY", "--json"}},
	}
	for _, c := range cases {
		dir := writeProbeProject(t, map[string]string{
			"compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n      " + c.env + "\n",
		})
		rt, out, errb := reportRT(dir)
		code := rt.Run(append(append([]string{}, c.args...), "--project-directory", dir))
		if code != exitcode.OK && code != exitcode.Safety {
			t.Errorf("%s: code=%d err=%s", c.name, code, errb.String())
		}
		assertNoSecret(t, c.name, c.secret, out.Bytes(), errb.Bytes())
	}
}
