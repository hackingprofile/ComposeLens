// SPDX-License-Identifier: Apache-2.0

package differential

import (
	"crypto/sha256"
	"crypto/subtle"
	"strings"

	"composelens/internal/evidence"
)

const withheldPlaceholder = "[redacted]"

const secretUncertainDetail = "secret values not comparable; no proven match or divergence"

func rawComparable(v string) bool {
	if v == withheldPlaceholder {
		return false
	}
	return !strings.Contains(v, withheldPlaceholder)
}

func fingerprintsEqual(left, right string) bool {
	hl := sha256.Sum256([]byte(left))
	hr := sha256.Sum256([]byte(right))
	return subtle.ConstantTimeCompare(hl[:], hr[:]) == 1
}

func secretBothVerdict(leftRaw, rightRaw string) (state, certainty, detail string) {
	if !rawComparable(leftRaw) || !rawComparable(rightRaw) {
		return StateUncertain, evidence.Unknown, secretUncertainDetail
	}
	if fingerprintsEqual(leftRaw, rightRaw) {
		return StateMatch, evidence.Proven, ""
	}
	return StateDivergent, evidence.Proven, ""
}
