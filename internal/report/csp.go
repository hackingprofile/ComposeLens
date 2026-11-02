// SPDX-License-Identifier: Apache-2.0

package report

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"

	"composelens/internal/safety"
)

// MaxHTMLBytes reuses the shared invocation cap so a rendered report cannot grow
// into an unbounded artifact. Overflow is CodeTotalTooLarge (CLI exit 3).
const MaxHTMLBytes = safety.MaxTotalBytes

func cspSHA256(body []byte) string {
	sum := sha256.Sum256(body)
	return "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
}

func cspPolicy(styleHash, bootHash, islandHash string) string {
	return strings.Join([]string{
		"default-src 'none'",
		"base-uri 'none'",
		"form-action 'none'",
		"object-src 'none'",
		"frame-ancestors 'none'",
		"img-src 'none'",
		"font-src 'none'",
		"connect-src 'none'",
		"media-src 'none'",
		"frame-src 'none'",
		"child-src 'none'",
		"worker-src 'none'",
		"manifest-src 'none'",
		"style-src '" + styleHash + "'",
		"script-src '" + bootHash + "' '" + islandHash + "'",
		"script-src-attr 'none'",
		"style-src-attr 'none'",
	}, "; ")
}
