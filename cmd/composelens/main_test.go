// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"strings"
	"testing"
)

func TestMainRecoversPanic(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(raw)
	if !strings.Contains(src, "recover()") || !strings.Contains(src, "RecoveredPanic") {
		t.Fatal("main must recover panics via cli.RecoveredPanic")
	}
}
