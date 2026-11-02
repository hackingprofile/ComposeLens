// SPDX-License-Identifier: Apache-2.0

package report

import (
	"fmt"
	"math"
	"strconv"
	"strings"
)

// Fixed report palette. CSS in html.go must use these exact hex values.
const (
	ColorText     = "#152033"
	ColorBg       = "#eef2f8"
	ColorCard     = "#ffffff"
	ColorNote     = "#3f4c63"
	ColorTabBg    = "#d5deee"
	ColorBrand    = "#1d4ed8"
	ColorFocus    = "#1d4ed8"
	ColorUIBorder = "#6c7690"
	ColorError    = "#b42318"
	ColorWarn     = "#8a5a00"
	ColorOkFg     = "#14532d"
	ColorOkBg     = "#c6f0d6"
	ColorAmberBg  = "#f8e4b0"
	ColorErrBg    = "#fadcd8"
	ColorChipBg   = "#e4ebf6"

	// Header band (deep navy) and its light text, used by the app-bar only.
	ColorBand        = "#0d2a54"
	ColorBandEyebrow = "#a9c2ef"
	ColorBandLede    = "#c3d2ec"
)

// ContrastPair is one WCAG 2.1 contrast check against the shipped palette.
type ContrastPair struct {
	Name string
	Fg   string
	Bg   string
	Min  float64 // 4.5 normal text, 3.0 large text / UI / focus
}

// PalettePairs is the complete AA table asserted by TestContrastAA.
func PalettePairs() []ContrastPair {
	return []ContrastPair{
		{Name: "body text on page", Fg: ColorText, Bg: ColorBg, Min: 4.5},
		{Name: "body text on card", Fg: ColorText, Bg: ColorCard, Min: 4.5},
		{Name: "note text on page", Fg: ColorNote, Bg: ColorBg, Min: 4.5},
		{Name: "note text on card", Fg: ColorNote, Bg: ColorCard, Min: 4.5},
		{Name: "tab text on tab background", Fg: ColorText, Bg: ColorTabBg, Min: 4.5},
		{Name: "selected tab text on card", Fg: ColorBrand, Bg: ColorCard, Min: 4.5},
		{Name: "brand heading on page", Fg: ColorBrand, Bg: ColorBg, Min: 4.5},
		{Name: "brand heading on card", Fg: ColorBrand, Bg: ColorCard, Min: 4.5},
		{Name: "option text on card", Fg: ColorText, Bg: ColorCard, Min: 4.5},
		{Name: "shadowed-chain text on card", Fg: ColorNote, Bg: ColorCard, Min: 4.5},
		{Name: "skip-link text on card", Fg: ColorText, Bg: ColorCard, Min: 4.5},
		{Name: "lede text on page", Fg: ColorNote, Bg: ColorBg, Min: 4.5},
		{Name: "error text on page", Fg: ColorError, Bg: ColorBg, Min: 4.5},
		{Name: "error text on card", Fg: ColorError, Bg: ColorCard, Min: 4.5},
		{Name: "warning text on page", Fg: ColorWarn, Bg: ColorBg, Min: 4.5},
		{Name: "warning text on card", Fg: ColorWarn, Bg: ColorCard, Min: 4.5},
		{Name: "info text on page", Fg: ColorBrand, Bg: ColorBg, Min: 4.5},
		{Name: "info text on card", Fg: ColorBrand, Bg: ColorCard, Min: 4.5},
		{Name: "ok badge text on fill", Fg: ColorOkFg, Bg: ColorOkBg, Min: 4.5},
		{Name: "warn badge text on fill", Fg: ColorWarn, Bg: ColorAmberBg, Min: 4.5},
		{Name: "error badge text on fill", Fg: ColorError, Bg: ColorErrBg, Min: 4.5},
		{Name: "notice badge text on fill", Fg: ColorNote, Bg: ColorTabBg, Min: 4.5},
		{Name: "type badge text on fill", Fg: ColorText, Bg: ColorTabBg, Min: 4.5},
		{Name: "chip text on chip fill", Fg: ColorText, Bg: ColorChipBg, Min: 4.5},
		{Name: "version badge on brand", Fg: ColorCard, Bg: ColorBrand, Min: 4.5},
		{Name: "wordmark on header band", Fg: ColorCard, Bg: ColorBand, Min: 4.5},
		{Name: "eyebrow on header band", Fg: ColorBandEyebrow, Bg: ColorBand, Min: 4.5},
		{Name: "lede on header band", Fg: ColorBandLede, Bg: ColorBand, Min: 4.5},
		{Name: "version badge text on white chip", Fg: ColorBand, Bg: ColorCard, Min: 4.5},
		{Name: "inactive tab text on page", Fg: ColorNote, Bg: ColorBg, Min: 4.5},
		{Name: "focus outline on page", Fg: ColorFocus, Bg: ColorBg, Min: 3.0},
		{Name: "focus outline on card", Fg: ColorFocus, Bg: ColorCard, Min: 3.0},
		{Name: "focus outline on tab background", Fg: ColorFocus, Bg: ColorTabBg, Min: 3.0},
		{Name: "selected-option border on card", Fg: ColorFocus, Bg: ColorCard, Min: 3.0},
		{Name: "UI border on page", Fg: ColorUIBorder, Bg: ColorBg, Min: 3.0},
		{Name: "UI border on card", Fg: ColorUIBorder, Bg: ColorCard, Min: 3.0},
		{Name: "UI border on tab background", Fg: ColorUIBorder, Bg: ColorTabBg, Min: 3.0},
	}
}

// ContrastRatio returns the WCAG 2.1 contrast ratio of two #RGB / #RRGGBB colors:
// (lighter + 0.05) / (darker + 0.05) after sRGB relative luminance.
func ContrastRatio(a, b string) (float64, error) {
	l1, err := relativeLuminance(a)
	if err != nil {
		return 0, err
	}
	l2, err := relativeLuminance(b)
	if err != nil {
		return 0, err
	}
	if l1 < l2 {
		l1, l2 = l2, l1
	}
	return (l1 + 0.05) / (l2 + 0.05), nil
}

func relativeLuminance(hex string) (float64, error) {
	r, g, b, err := parseHex(hex)
	if err != nil {
		return 0, err
	}
	R := wcagChannel(float64(r) / 255)
	G := wcagChannel(float64(g) / 255)
	B := wcagChannel(float64(b) / 255)
	return 0.2126*R + 0.7152*G + 0.0722*B, nil
}

func wcagChannel(srgb float64) float64 {
	if srgb <= 0.03928 {
		return srgb / 12.92
	}
	return math.Pow((srgb+0.055)/1.055, 2.4)
}

func parseHex(hex string) (r, g, b uint8, err error) {
	h := strings.TrimPrefix(strings.TrimSpace(hex), "#")
	switch len(h) {
	case 3:
		h = string([]byte{h[0], h[0], h[1], h[1], h[2], h[2]})
	case 6:
	default:
		return 0, 0, 0, fmt.Errorf("hex color %q", hex)
	}
	v, err := strconv.ParseUint(h, 16, 32)
	if err != nil {
		return 0, 0, 0, err
	}
	return uint8(v >> 16), uint8(v >> 8), uint8(v), nil
}
