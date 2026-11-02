// SPDX-License-Identifier: Apache-2.0

package report

import (
	"strings"
	"testing"
)

func TestContrastAA(t *testing.T) {
	css := htmlCSS
	for _, c := range []string{ColorText, ColorBg, ColorCard, ColorNote, ColorTabBg, ColorBrand, ColorFocus, ColorUIBorder, ColorError, ColorWarn, ColorOkFg, ColorOkBg, ColorAmberBg, ColorErrBg, ColorChipBg} {
		if !strings.Contains(css, c) {
			t.Fatalf("palette %s missing from CSS", c)
		}
	}
	for _, p := range PalettePairs() {
		ratio, err := ContrastRatio(p.Fg, p.Bg)
		if err != nil {
			t.Fatalf("%s: %v", p.Name, err)
		}
		if ratio+1e-9 < p.Min {
			t.Fatalf("%s %s on %s ratio=%.2f want >= %.1f", p.Name, p.Fg, p.Bg, ratio, p.Min)
		}
		t.Logf("%s\t%s on %s\t%.2f:1\tAA>=%.1f\tPASS", p.Name, p.Fg, p.Bg, ratio, p.Min)
	}
}

func TestContrastKnownPair(t *testing.T) {
	ratio, err := ContrastRatio("#000000", "#ffffff")
	if err != nil {
		t.Fatal(err)
	}
	if ratio < 20.9 || ratio > 21.1 {
		t.Fatalf("black/white ratio=%.3f want 21", ratio)
	}
}
