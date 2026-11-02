// SPDX-License-Identifier: Apache-2.0

package redact

import (
	"strings"
	"testing"
)

// Every value of every credential query key, and every DSN password,
// is a credential; an unparseable credential query is never credential-free.
func TestEveryCredentialQueryValueAndDSNPasswordIsCollected(t *testing.T) {
	cases := []struct {
		value string
		want  []string
	}{
		{"https://example.test/?api_key=&api_key=solar-secretvalue", []string{"solar-secretvalue"}},
		{"https://example.test/?api_key=solar-firstsecretvalue&api_key=solar-secondsecretvalue", []string{"solar-firstsecretvalue", "solar-secondsecretvalue"}},
		{"https://example.test/?password=solar-secretvalue;mode=rw", []string{"solar-secretvalue"}},
		{"https://example.test/?password=solar-secretvalue%zz", []string{"solar-secretvalue%zz"}},
		{"https://example.test/?mode=rw&token=solar-later-secret", []string{"solar-later-secret"}},
		{"https://example.test/?password=abc&password=solar-second", []string{"abc", "solar-second"}},
		{"server=example.test;password=solar-firstsecretvalue;password=solar-secondsecretvalue", []string{"solar-firstsecretvalue", "solar-secondsecretvalue"}},
	}
	for _, c := range cases {
		if !LooksLikeSecret(c.value) {
			t.Errorf("%q not classified as a credential", c.value)
		}
		frags := SecretFragments(c.value)
		for _, w := range c.want {
			found := false
			for _, f := range frags {
				if f == w {
					found = true
				}
			}
			if !found {
				t.Errorf("%q: fragment %q not collected (got %d fragments)", c.value, w, len(frags))
			}
		}
	}
	for _, public := range []string{"https://example.test/?mode=rw&page=2", "https://example.test/path", "https://example.test/?api_key="} {
		if LooksLikeSecret(public) {
			t.Errorf("%q has no credential value but was classified secret", public)
		}
		if strings.Contains(strings.Join(SecretFragments(public)[1:], ","), "mode") {
			t.Errorf("%q: public query value collected", public)
		}
	}
}
