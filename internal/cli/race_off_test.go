// SPDX-License-Identifier: Apache-2.0

//go:build !race

package cli

// raceEnabled is true when the tests run under the race detector, which
// slows execution several-fold.
const raceEnabled = false
