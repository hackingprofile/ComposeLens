// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// ErrInputTooLarge is returned when a bounded read would exceed maxBytes.
var ErrInputTooLarge = errors.New("input exceeds declared byte bound")

// ErrNotRegularFile is returned for a device, FIFO, socket or pseudo-file
// (/proc, /sys, /dev). Such a path is never opened for reading.
var ErrNotRegularFile = errors.New("not a regular file")

// ReadAtMost opens path and reads at most maxBytes. It refuses an oversized
// file from Stat before allocating the contents, then reads at most maxBytes+1
// so a size change between stat and read is still detected.
func ReadAtMost(path string, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxFileBytes
	}
	if st, err := os.Stat(path); err == nil && !st.IsDir() && !st.Mode().IsRegular() {
		return nil, ErrNotRegularFile
	}
	if pseudoFile(path) {
		return nil, ErrNotRegularFile
	}
	// Opened non-blocking where the platform supports it, so a path swapped
	// for a FIFO after the check cannot block the open.
	f, err := os.OpenFile(path, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if st, err := f.Stat(); err == nil {
		if st.IsDir() {
			return nil, os.ErrInvalid
		}
		if !st.Mode().IsRegular() {
			return nil, ErrNotRegularFile
		}
		if st.Size() > int64(maxBytes) {
			return nil, ErrInputTooLarge
		}
	}
	raw, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, ErrInputTooLarge
	}
	return raw, nil
}

// ReadAtMostFrom reads at most maxBytes from r. It never retains more than
// maxBytes+1, so a hostile infinite/huge stream cannot grow unbounded.
func ReadAtMostFrom(r io.Reader, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxEngineOutputBytes
	}
	raw, err := io.ReadAll(io.LimitReader(r, int64(maxBytes)+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxBytes {
		return nil, ErrInputTooLarge
	}
	return raw, nil
}

// ReadCharged is ReadAtMost plus Budget.ChargePath. A nil budget still
// enforces the per-file byte cap.
func ReadCharged(b *Budget, path string, maxBytes int) ([]byte, error) {
	if maxBytes <= 0 {
		maxBytes = MaxFileBytes
	}
	raw, err := ReadAtMost(path, maxBytes)
	if err != nil {
		if errors.Is(err, ErrInputTooLarge) {
			return nil, NewParseError(CodeFileTooLarge, path, fmt.Sprintf("file exceeds %d bytes", maxBytes))
		}
		if errors.Is(err, ErrNotRegularFile) {
			return nil, NewParseError(CodeNotRegularFile, path, "not a regular file (device, FIFO, socket or pseudo-file); it is not read")
		}
		return nil, err
	}
	if err := b.ChargePath(path, len(raw)); err != nil {
		return nil, err
	}
	return raw, nil
}

// BoundBuffer is an io.Writer that retains at most Max bytes and reports
// Overflow when more would have been written. Extra bytes are discarded
// so allocation stays capped.
type BoundBuffer struct {
	Max      int
	buf      bytes.Buffer
	overflow bool
}

func (b *BoundBuffer) Write(p []byte) (int, error) {
	if b.Max <= 0 {
		b.Max = MaxEngineOutputBytes
	}
	if b.overflow {
		return len(p), nil
	}
	room := b.Max - b.buf.Len()
	if len(p) > room {
		if room > 0 {
			_, _ = b.buf.Write(p[:room])
		}
		b.overflow = true
		return len(p), nil
	}
	return b.buf.Write(p)
}

func (b *BoundBuffer) Bytes() []byte { return b.buf.Bytes() }

func (b *BoundBuffer) String() string { return b.buf.String() }

func (b *BoundBuffer) Len() int { return b.buf.Len() }

func (b *BoundBuffer) Overflow() bool { return b.overflow }
