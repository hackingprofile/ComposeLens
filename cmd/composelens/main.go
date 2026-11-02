// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"

	"composelens/internal/cli"
)

func main() {
	os.Exit(run())
}

func run() (code int) {
	defer func() {
		if rec := recover(); rec != nil {
			code = cli.RecoveredPanic(os.Stderr, rec)
		}
	}()
	return cli.Run(os.Args[1:], os.Stdout, os.Stderr, os.Environ())
}
