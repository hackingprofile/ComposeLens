// SPDX-License-Identifier: Apache-2.0

package containerenv

import (
	"os"
	"path/filepath"
	"testing"

	"composelens/internal/composeparse"
	"composelens/internal/discover"
	"composelens/internal/merge"
)

func loadContainerenvFixture(t *testing.T, rel string) []merge.Field {
	t.Helper()
	p := filepath.Join("..", "..", "fixtures", "containerenv", filepath.FromSlash(rel))
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
	return merge.Documents([]*composeparse.Document{d}, nil)
}

func TestOfficialOverrideFixture(t *testing.T) {
	m := varsOf(mustResolve(t, loadContainerenvFixture(t, "override/compose.yaml"), nil, nil), "web")
	if m["COLOR"].Value != "from-compose" || m["COLOR"].Winner.Kind != KindEnvironment {
		t.Fatalf("%+v", m["COLOR"])
	}
}

func TestOfficialOrderFixture(t *testing.T) {
	m := varsOf(mustResolve(t, loadContainerenvFixture(t, "order/compose.yaml"), nil, nil), "web")
	if m["SHARED"].Value != "from-b" {
		t.Fatalf("%+v", m["SHARED"])
	}
}

func TestOfficialPassThroughFixture(t *testing.T) {
	host := map[string]string{"DEBUG": "from-shell"}
	m := varsOf(mustResolve(t, loadContainerenvFixture(t, "passthrough/compose.yaml"), host, nil), "web")
	if m["DEBUG"].Value != "from-shell" || m["DEBUG"].Winner.Kind != KindHostShell {
		t.Fatalf("%+v", m["DEBUG"])
	}
}

func TestOfficialMultiSourceFixture(t *testing.T) {
	m := varsOf(mustResolve(t, loadContainerenvFixture(t, "multi/compose.yaml"), nil, nil), "web")
	if m["COLOR"].Value != "from-compose" || len(m["COLOR"].Overridden) < 2 {
		t.Fatalf("%+v", m["COLOR"])
	}
}
