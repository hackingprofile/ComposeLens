// SPDX-License-Identifier: Apache-2.0

package digest

import (
	"crypto/sha256"
	"encoding/hex"
)

func Bytes(b []byte) string {
	sum := sha256.Sum256(b)
	return "sha256:" + hex.EncodeToString(sum[:])
}
