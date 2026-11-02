// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"fmt"
	"sync"
)

// Budget is the shared untrusted-input accounting for one CLI invocation.
// Unique paths are charged once so discover + include/extends/env/policy
// cannot double-count the same file. Engine streams are charged separately
// (no file-count) against the same byte aggregate.
type Budget struct {
	mu    sync.Mutex
	bytes int64
	files int
	seen  map[string]struct{}
}

func NewBudget() *Budget {
	return &Budget{seen: map[string]struct{}{}}
}

func Optional(budgets []*Budget) *Budget {
	if len(budgets) == 0 {
		return nil
	}
	return budgets[0]
}

func (b *Budget) Bytes() int64 {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.bytes
}

func (b *Budget) Files() int {
	if b == nil {
		return 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.files
}

// ChargePath records one unique file toward MaxTotalFiles and MaxTotalBytes.
// A second charge of the same path is a no-op.
func (b *Budget) ChargePath(path string, n int) error {
	if b == nil {
		return nil
	}
	if n < 0 {
		n = 0
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.seen == nil {
		b.seen = map[string]struct{}{}
	}
	if _, ok := b.seen[path]; ok {
		return nil
	}
	if b.files+1 > MaxTotalFiles {
		return NewParseError(CodeTooManyFiles, path, fmt.Sprintf("input exceeds %d files", MaxTotalFiles))
	}
	if b.bytes+int64(n) > int64(MaxTotalBytes) {
		return NewParseError(CodeTotalTooLarge, path, fmt.Sprintf("total input exceeds %d bytes", MaxTotalBytes))
	}
	b.seen[path] = struct{}{}
	b.files++
	b.bytes += int64(n)
	return nil
}

// ChargeStream records engine stdout/stderr bytes against MaxTotalBytes.
// A single stream larger than MaxEngineOutputBytes is refused first.
func (b *Budget) ChargeStream(n int) error {
	if b == nil {
		return nil
	}
	if n < 0 {
		n = 0
	}
	if n > MaxEngineOutputBytes {
		return NewParseError(CodeEngineOutputTooLarge, "", fmt.Sprintf("engine output exceeds %d bytes", MaxEngineOutputBytes))
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.bytes+int64(n) > int64(MaxTotalBytes) {
		return NewParseError(CodeTotalTooLarge, "", fmt.Sprintf("total input exceeds %d bytes", MaxTotalBytes))
	}
	b.bytes += int64(n)
	return nil
}
