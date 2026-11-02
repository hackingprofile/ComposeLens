// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestCatalogPreservesPOSIXBackslashFileName(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(fixturesRoot(t), "catalog.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var cat struct {
		Fixtures []struct {
			ID       string `yaml:"id"`
			Expected struct {
				Fields []struct {
					Path  string `yaml:"path"`
					POSIX string `yaml:"posixValue"`
				} `yaml:"engineFields"`
			} `yaml:"expected"`
		} `yaml:"fixtures"`
	}
	if err := yaml.Unmarshal(raw, &cat); err != nil {
		t.Fatal(err)
	}
	for _, fx := range cat.Fixtures {
		if fx.ID != "platform.paths.rel-backslash" {
			continue
		}
		for _, field := range fx.Expected.Fields {
			if field.Path == "services.web.volumes" {
				want := `type=bind source={project}/.\rel target=/in{optional: create_host_path=true}`
				if field.POSIX != want {
					t.Fatalf("POSIX engine value = %q, want %q", field.POSIX, want)
				}
				return
			}
		}
	}
	t.Fatal("relative backslash bind missing from catalog")
}
