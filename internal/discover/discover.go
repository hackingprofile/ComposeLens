// SPDX-License-Identifier: Apache-2.0

package discover

import (
	"os"
	"path/filepath"
	"strings"

	"composelens/internal/digest"
	"composelens/internal/evidence"
	"composelens/internal/paths"
	"composelens/internal/safety"
)

var defaultNames = []string{
	"compose.yaml",
	"compose.yml",
	"docker-compose.yaml",
	"docker-compose.yml",
}

var overrideNames = []string{
	"compose.override.yaml",
	"compose.override.yml",
}

type File struct {
	Path   string
	Digest string
	Origin string
	Index  int
	Bytes  []byte `json:"-"`
}

func SplitComposeFileEnv(v string) []string {
	if strings.TrimSpace(v) == "" {
		return nil
	}
	parts := strings.Split(v, string(os.PathListSeparator))
	var out []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func Discover(cwd, projectDir string, explicit []string, composeFileEnv string, budget ...*safety.Budget) ([]File, error) {
	b := safety.Optional(budget)
	if b == nil {
		b = safety.NewBudget()
	}
	if len(explicit) > 0 {
		return loadList(cwd, explicit, evidence.OriginFlag, b)
	}
	fromEnv := SplitComposeFileEnv(composeFileEnv)
	if len(fromEnv) > 0 {
		return loadList(cwd, fromEnv, evidence.OriginEnv, b)
	}
	return loadDefaults(projectDir, b)
}

func loadList(cwd string, list []string, origin string, b *safety.Budget) ([]File, error) {
	out := make([]File, 0, len(list))
	for i, item := range list {
		resolved, err := paths.Resolve(cwd, item)
		if err != nil {
			return nil, err
		}
		f, err := readFile(resolved, origin, i, b)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, nil
}

func loadDefaults(projectDir string, b *safety.Budget) ([]File, error) {
	var chosen string
	for _, name := range defaultNames {
		p := filepath.Join(projectDir, name)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			chosen = p
			break
		}
	}
	if chosen == "" {
		return nil, nil
	}
	base, err := readFile(chosen, evidence.OriginDefault, 0, b)
	if err != nil {
		return nil, err
	}
	out := []File{base}
	baseName := filepath.Base(chosen)
	if baseName == "compose.yaml" || baseName == "compose.yml" {
		for _, ov := range overrideNames {
			p := filepath.Join(projectDir, ov)
			if st, err := os.Stat(p); err == nil && !st.IsDir() {
				f, err := readFile(p, evidence.OriginDefault, len(out), b)
				if err != nil {
					return nil, err
				}
				out = append(out, f)
				break
			}
		}
	}
	return out, nil
}

func readFile(canonical string, origin string, index int, b *safety.Budget) (File, error) {
	abs, err := paths.Canonical(canonical)
	if err != nil {
		return File{}, err
	}
	raw, err := safety.ReadCharged(b, abs, safety.MaxFileBytes)
	if err != nil {
		return File{}, err
	}
	return File{
		Path:   abs,
		Digest: digest.Bytes(raw),
		Origin: origin,
		Index:  index,
		Bytes:  raw,
	}, nil
}
