// SPDX-License-Identifier: Apache-2.0

package shortvol

import "testing"

func TestParseMatrix(t *testing.T) {
	cases := []struct {
		raw                  string
		source, target, mode string
		ok                   bool
	}{
		{raw: `C:\Alpha:/data`, source: `C:\Alpha`, target: `/data`, ok: true},
		{raw: `C:\Alpha:/data:ro`, source: `C:\Alpha`, target: `/data`, mode: `ro`, ok: true},
		{raw: `C:\Alpha:/data:rw`, source: `C:\Alpha`, target: `/data`, mode: `rw`, ok: true},
		{raw: `D:/Beta:/data`, source: `D:/Beta`, target: `/data`, ok: true},
		{raw: `./rel:/data`, source: `./rel`, target: `/data`, ok: true},
		{raw: `/abs:/data`, source: `/abs`, target: `/data`, ok: true},
		{raw: `named:/data`, source: `named`, target: `/data`, ok: true},
		{raw: `/data`, target: `/data`, ok: true},
		{raw: `./a:/data:z`, source: `./a`, target: `/data`, mode: `z`, ok: true},
		{raw: "", ok: false},
		{raw: "{type: bind}", ok: false},
	}
	for _, tc := range cases {
		got, ok := Parse(tc.raw)
		if ok != tc.ok {
			t.Fatalf("%q: ok=%v want %v", tc.raw, ok, tc.ok)
		}
		if !tc.ok {
			continue
		}
		if got.Source != tc.source || got.Target != tc.target || got.Mode != tc.mode {
			t.Fatalf("%q: got %+v want source=%q target=%q mode=%q", tc.raw, got, tc.source, tc.target, tc.mode)
		}
	}
}

func TestTargetDriveLetterNotHostFragment(t *testing.T) {
	if Target(`C:\Alpha:/data`) != `/data` {
		t.Fatalf("got %q", Target(`C:\Alpha:/data`))
	}
	if Target(`D:\Beta:/data`) != `/data` {
		t.Fatalf("got %q", Target(`D:\Beta:/data`))
	}
	if Target(`C:\Alpha:/data`) != Target(`D:\Beta:/data`) {
		t.Fatal("same container target must share the unique key")
	}
	if Target(`C:\Alpha:/data`) == Target(`D:\Beta:/other`) {
		t.Fatal("different targets must not share a key")
	}
}

func TestWindowsDrive(t *testing.T) {
	if !WindowsDrive(`C:\Alpha`) || !WindowsDrive(`D:/Beta`) {
		t.Fatal("drive prefix")
	}
	if WindowsDrive(`/abs`) || WindowsDrive(`named`) || WindowsDrive(`./rel`) {
		t.Fatal("non-drive")
	}
}
