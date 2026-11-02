// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package safety

const openNonblock = 0

// pseudoFile is false where there is no kernel pseudo-file system; devices
// and named pipes are refused by their file mode.
func pseudoFile(string) bool { return false }
