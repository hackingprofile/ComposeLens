// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
)

func loadMergeFixture(t *testing.T, name string) *composeparse.Document {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "merge", name)
	raw, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		t.Fatal(err)
	}
	d, err := composeparse.Parse(discover.File{Path: abs, Bytes: raw, Origin: "fixture"})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestOfficialFixturesMapListScalar(t *testing.T) {
	fields := Documents([]*composeparse.Document{
		loadMergeFixture(t, "base.yaml"),
		loadMergeFixture(t, "overlay.yaml"),
	}, nil)
	m := byPath(fields)
	if m["services.web.image"].Value != "redis" {
		t.Fatalf("scalar %+v", m["services.web.image"])
	}
	if m["services.web.hostname"].Value != "from-base" {
		t.Fatalf("kept hostname %+v", m["services.web.hostname"])
	}
	if m["services.web.environment.A"].Value != "one" || m["services.web.environment.B"].Value != "two-b" || m["services.web.environment.C"].Value != "three" {
		t.Fatalf("map merge A=%+v B=%+v C=%+v", m["services.web.environment.A"], m["services.web.environment.B"], m["services.web.environment.C"])
	}
	if m["services.web.ports"].Value != "[80:80, 443:443, 8080:80]" || m["services.web.ports"].Action != ActionAppend {
		t.Fatalf("list %+v", m["services.web.ports"])
	}
}

func TestResetFixture(t *testing.T) {
	fields := Documents([]*composeparse.Document{
		loadMergeFixture(t, "base.yaml"),
		loadMergeFixture(t, "reset.yaml"),
	}, nil)
	m := byPath(fields)
	if m["services.web.environment"].Action != ActionReset {
		t.Fatalf("reset %+v", m["services.web.environment"])
	}
	if _, ok := m["services.web.environment.A"]; ok {
		t.Fatal("children remain")
	}
}

func TestOverrideFixture(t *testing.T) {
	fields := Documents([]*composeparse.Document{
		loadMergeFixture(t, "base.yaml"),
		loadMergeFixture(t, "override.yaml"),
	}, nil)
	m := byPath(fields)
	if _, ok := m["services.web.environment.A"]; ok {
		t.Fatal("A should be dropped by !override")
	}
	if m["services.web.environment.ONLY"].Value != "kept" {
		t.Fatalf("ONLY %+v", m["services.web.environment.ONLY"])
	}
}

func TestFixtureWinnerPaths(t *testing.T) {
	fields := Documents([]*composeparse.Document{
		loadMergeFixture(t, "base.yaml"),
		loadMergeFixture(t, "overlay.yaml"),
	}, nil)
	img := byPath(fields)["services.web.image"]
	if !strings.HasSuffix(img.Winner, "overlay.yaml") {
		t.Fatalf("winner %s", img.Winner)
	}
}

func TestOfficialFixtureThreeFileOrder(t *testing.T) {
	fields := Documents([]*composeparse.Document{
		loadMergeFixture(t, "base.yaml"),
		loadMergeFixture(t, "overlay.yaml"),
		loadMergeFixture(t, "third.yaml"),
	}, nil)
	img := byPath(fields)["services.web.image"]
	if img.Value != "alpine" || !strings.HasSuffix(img.Winner, "third.yaml") {
		t.Fatalf("image %+v", img)
	}
	if len(img.Overridden) != 2 || img.Overridden[0].Value != "nginx" || img.Overridden[1].Value != "redis" {
		t.Fatalf("overridden %+v", img.Overridden)
	}
}
