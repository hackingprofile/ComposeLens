// SPDX-License-Identifier: Apache-2.0

package report

import _ "embed"

// Embedded report JSON Schema. go:embed cannot use .., so this file is a
// byte-identical copy of schemas/composelens.report.v0.json (enforced by test).
//
//go:embed embedded/composelens.report.v0.json
var embeddedReportSchema []byte

// EmbeddedReportSchema returns the composelens.report.v0 JSON Schema bytes
// shipped in the CLI binary. Validation of generated packages stays in
// ValidateBytes and does not parse this document at runtime.
func EmbeddedReportSchema() []byte {
	return embeddedReportSchema
}
