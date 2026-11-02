// SPDX-License-Identifier: Apache-2.0

package safety

import "testing"

func TestGuardRefusesUnclassifiedSecretShapedOutput(t *testing.T) {
	for _, out := range []string{
		"value=4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a\n",
		`{"text": "Zm9vYmFyYmF6cXV4MTIzNDU2Nzg5MGFiY2RlZg"}`,
	} {
		if err := Guard([]byte(out), nil); err == nil {
			t.Errorf("Guard(%q) allowed an unclassified secret-shaped value", out)
		}
	}
}

func TestGuardAllowsDigestsFingerprintsAndOrdinaryText(t *testing.T) {
	for _, out := range []string{
		"sha256:a9085a967708f9e8622bb5c9e4b7a14ee54e44283f2743063158d7de0afc0ecd\n",
		`"fingerprint": "hmac-sha256:dbf76566c33a3c88f9ac08c87636d8de"`,
		"image: nginx@sha256:0d17b565c37bcbd895e9d92315a05c1c3c9a29f762b011a10c54a66cd53c9b31\n",
		`C:\Users\x\AppData\Local\Temp\TestSecretUnderSecretNamedMappingInterpolatedIsWithheld380355528\001` + "\n",
		"<script integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\">",
		"Services: 3 (web, api, db)\n",
	} {
		if err := Guard([]byte(out), nil); err != nil {
			t.Errorf("Guard(%q) refused ordinary output: %v", out, err)
		}
	}
}
