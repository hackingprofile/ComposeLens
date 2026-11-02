// SPDX-License-Identifier: Apache-2.0

//go:build unix

package cli

import "syscall"

// openNoFollow refuses a symbolic link as the last path element when an
// output file is opened.
const openNoFollow = syscall.O_NOFOLLOW
