// SPDX-License-Identifier: Apache-2.0

package safety

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBudgetUniquePathAndAggregate(t *testing.T) {
	b := NewBudget()
	if err := b.ChargePath("a.yaml", MaxTotalBytes-10); err != nil {
		t.Fatal(err)
	}
	if err := b.ChargePath("a.yaml", MaxTotalBytes); err != nil {
		t.Fatal("second charge of same path must be a no-op")
	}
	err := b.ChargePath("b.yaml", 20)
	if err == nil || CodeOf(err) != CodeTotalTooLarge || !IsResourceBound(err) {
		t.Fatalf("got %v", err)
	}
}

func TestBudgetFileCount(t *testing.T) {
	b := NewBudget()
	for i := 0; i < MaxTotalFiles; i++ {
		if err := b.ChargePath(string(rune('a'+i%26))+filepath.FromSlash("/")+itoa(i), 1); err != nil {
			t.Fatalf("file %d: %v", i, err)
		}
	}
	err := b.ChargePath("overflow.yaml", 1)
	if CodeOf(err) != CodeTooManyFiles {
		t.Fatalf("got %s %v", CodeOf(err), err)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d [16]byte
	i := len(d)
	for n > 0 {
		i--
		d[i] = byte('0' + n%10)
		n /= 10
	}
	return string(d[i:])
}

func TestBudgetChargeStreamEngineCap(t *testing.T) {
	b := NewBudget()
	if err := b.ChargeStream(MaxEngineOutputBytes); err != nil {
		t.Fatal(err)
	}
	if err := b.ChargeStream(MaxEngineOutputBytes + 1); CodeOf(err) != CodeEngineOutputTooLarge {
		t.Fatalf("got %v", err)
	}
}

func TestBudgetNilIsNoop(t *testing.T) {
	var b *Budget
	if err := b.ChargePath("x", 99); err != nil {
		t.Fatal(err)
	}
	if err := b.ChargeStream(99); err != nil {
		t.Fatal(err)
	}
}

func TestReadChargedAndSecretSafePath(t *testing.T) {
	dir := t.TempDir()
	probe := "ghp_" + "abcdefghijklmnopqrstuvwxyz0123456789"
	p := filepath.Join(dir, probe)
	if err := os.WriteFile(p, []byte("services:\n  web:\n    image: alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := NewBudget()
	if err := b.ChargePath("precharged.yaml", MaxTotalBytes-8); err != nil {
		t.Fatal(err)
	}
	_, err := ReadCharged(b, p, MaxFileBytes)
	if !IsResourceBound(err) || CodeOf(err) != CodeTotalTooLarge {
		t.Fatalf("got %v", err)
	}
	msg := err.Error()
	if strings.Contains(msg, probe) {
		t.Fatalf("leaked secret path: %s", msg)
	}
	if strings.Contains(msg, "image: alpine") {
		t.Fatalf("leaked content: %s", msg)
	}
}

func TestBoundBufferAndReadAtMostFrom(t *testing.T) {
	var buf BoundBuffer
	buf.Max = 8
	n, err := buf.Write([]byte("abcdefghij"))
	if err != nil || n != 10 {
		t.Fatalf("write %d %v", n, err)
	}
	if !buf.Overflow() || buf.Len() != 8 || buf.String() != "abcdefgh" {
		t.Fatalf("buf=%q overflow=%v", buf.String(), buf.Overflow())
	}
	if _, err := buf.Write([]byte("more")); err != nil {
		t.Fatal(err)
	}
	if buf.Len() != 8 {
		t.Fatalf("grew past cap: %d", buf.Len())
	}

	raw, err := ReadAtMostFrom(bytes.NewReader([]byte("abcd")), 4)
	if err != nil || string(raw) != "abcd" {
		t.Fatalf("exact %q %v", raw, err)
	}
	_, err = ReadAtMostFrom(&ones{}, 64)
	if !errors.Is(err, ErrInputTooLarge) {
		t.Fatalf("infinite: %v", err)
	}
	limited, err := ReadAtMostFrom(io.LimitReader(&ones{}, 32), 64)
	if err != nil || len(limited) != 32 {
		t.Fatalf("limited %d %v", len(limited), err)
	}
}

type ones struct{}

func (ones) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	return len(p), nil
}
