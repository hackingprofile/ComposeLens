// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import "testing"

func TestProjectEnvSymlinkConfinementOnUnix(t *testing.T) {
	TestProjectEnvSymlinkOutsideIsWithheld(t)
}
