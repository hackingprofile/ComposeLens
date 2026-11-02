// SPDX-License-Identifier: Apache-2.0

package safety

import "testing"

func TestPublicRevisionsDoNotExemptKnownSecrets(t *testing.T) {
	revision := "4f9a8c2e7b1d6f3a0c5e8b2d7f1a4c6e9b3d5f8a"
	if err := GuardWithRevisions([]byte(revision), nil, []string{revision}); err != nil {
		t.Fatal(err)
	}
	if err := GuardWithRevisions([]byte(revision), []string{revision}, []string{revision}); err == nil {
		t.Fatal("public revision exempted a known secret")
	}
	if err := GuardWithRevisions([]byte("a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"), nil, []string{"a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6"}); err == nil {
		t.Fatal("non-revision token accepted as a revision")
	}
}
