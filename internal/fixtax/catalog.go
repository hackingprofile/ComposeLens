// SPDX-License-Identifier: Apache-2.0

package fixtax

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func LoadCatalog(path string) (Catalog, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return Catalog{}, err
	}
	var c Catalog
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return Catalog{}, err
	}
	if c.Schema != Schema {
		return Catalog{}, fmt.Errorf("catalog schema %q want %s", c.Schema, Schema)
	}
	seen := map[string]struct{}{}
	for i, f := range c.Fixtures {
		if f.ID == "" || f.Feature == "" || f.Kind == "" || f.Description == "" {
			return Catalog{}, fmt.Errorf("fixture[%d] missing id/feature/kind/description", i)
		}
		if !validEngine(f.Expected.Engine) {
			return Catalog{}, fmt.Errorf("%s: engine expected must be %s, %s, %s, or %s, not guessed (%q)", f.ID, EnginePending, EngineMatched, EngineDivergent, EngineError, f.Expected.Engine)
		}
		if f.Expected.Engine != EnginePending && strings.TrimSpace(f.Expected.EnginePin) == "" {
			return Catalog{}, fmt.Errorf("%s: engine-anchored row requires enginePin", f.ID)
		}
		if (f.Expected.Engine == EngineMatched || f.Expected.Engine == EngineDivergent) && len(f.Expected.EngineFields) == 0 {
			return Catalog{}, fmt.Errorf("%s: %s row requires engineFields from the live engine", f.ID, f.Expected.Engine)
		}
		if f.Expected.Local.Assertion == "" {
			return Catalog{}, fmt.Errorf("%s: missing local assertion", f.ID)
		}
		if len(f.Files) == 0 {
			return Catalog{}, fmt.Errorf("%s: no files declared", f.ID)
		}
		if !validKind(f.Kind) {
			return Catalog{}, fmt.Errorf("%s: unknown kind %q", f.ID, f.Kind)
		}
		if (f.Kind == KindRegression || f.Kind == KindPlatform) && EngineAnchored(f) {
			if err := validRationale(f); err != nil {
				return Catalog{}, fmt.Errorf("%s: %w", f.ID, err)
			}
		}
		if f.Kind == KindSecurity {
			if err := validRationale(f); err != nil {
				return Catalog{}, fmt.Errorf("%s: %w", f.ID, err)
			}
		}
		if _, ok := seen[f.ID]; ok {
			return Catalog{}, fmt.Errorf("duplicate fixture id %s", f.ID)
		}
		seen[f.ID] = struct{}{}
	}
	return c, nil
}

func validEngine(s string) bool {
	switch s {
	case EnginePending, EngineMatched, EngineDivergent, EngineError:
		return true
	default:
		return false
	}
}

func validKind(k string) bool {
	switch k {
	case KindBaseline, KindRegression, KindPlatform, KindAdversarial, KindSecurity:
		return true
	default:
		return false
	}
}

func validRationale(f Fixture) error {
	switch f.Rationale.Type {
	case "compose-spec", "docs":
	case "issue":
		return fmt.Errorf("rationale type issue is only allowed for a verified GitHub URL; this corpus does not cite issues")
	default:
		return fmt.Errorf("rationale row requires rationale.type compose-spec or docs, got %q", f.Rationale.Type)
	}
	if strings.TrimSpace(f.Rationale.Ref) == "" {
		return fmt.Errorf("rationale row requires rationale.ref")
	}
	if !strings.HasPrefix(f.Rationale.Ref, "https://") {
		return fmt.Errorf("rationale.ref must be an https URL, got %q", f.Rationale.Ref)
	}
	if strings.Contains(f.Rationale.Ref, "github.com/docker/compose/issues/") {
		return fmt.Errorf("do not cite docker/compose issue URLs unless verified; use compose-spec or docs")
	}
	return nil
}

func FixtureFiles(root string) ([]string, error) {
	var out []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		base := filepath.Base(path)
		if skipDeclaredName(base, rel) {
			return nil
		}
		ext := strings.ToLower(filepath.Ext(path))
		if ext == ".yaml" || ext == ".yml" || ext == ".json" || ext == ".env" || base == ".env" {
			out = append(out, rel)
		}
		return nil
	})
	return out, err
}

func skipDeclaredName(base, rel string) bool {
	switch base {
	case "README.md", "catalog.yaml", "TAXONOMY.md", "meta.yaml":
		return true
	}
	return strings.HasSuffix(rel, "/README.md")
}

func Undeclared(root string, cat Catalog) ([]string, error) {
	onDisk, err := FixtureFiles(root)
	if err != nil {
		return nil, err
	}
	declared := map[string]struct{}{}
	for _, f := range cat.Fixtures {
		for _, p := range f.Files {
			declared[filepath.ToSlash(p)] = struct{}{}
		}
	}
	var missing []string
	for _, p := range onDisk {
		if _, ok := declared[p]; !ok {
			missing = append(missing, p)
		}
	}
	return missing, nil
}
