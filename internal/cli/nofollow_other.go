// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package cli

// openNoFollow is 0 where the platform has no O_NOFOLLOW; output paths are
// checked with Lstat before they are opened.
const openNoFollow = 0
