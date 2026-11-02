// SPDX-License-Identifier: Apache-2.0

package exitcode

// Process exits: 0 success, 1 internal, 2 usage, 3 input, 4 safety
// (fail-closed), 5 unsupported, 6 check assertion (severity gate).
const (
	OK          = 0
	Internal    = 1
	Usage       = 2
	Input       = 3
	Safety      = 4
	Unsupported = 5
	// Assertion is a check severity-gate failure. It must not collide with 0–5.
	Assertion = 6
)
