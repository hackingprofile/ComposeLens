// SPDX-License-Identifier: Apache-2.0

package merge

import (
	"strings"
	"testing"
)

func TestUniqueSecretsConfigsEnvDependsOn(t *testing.T) {
	fields := Documents(docsFrom(t,
		"base.yaml", "services:\n  web:\n    secrets:\n      - a\n    configs:\n      - c1\n    environment:\n      - FOO=1\n    depends_on:\n      - db\n",
		"over.yaml", "services:\n  web:\n    secrets:\n      - a\n      - b\n    configs:\n      - source: c1\n      - source: c2\n    environment:\n      - FOO=2\n      - BAR=3\n    depends_on:\n      db:\n        condition: service_started\n      api:\n",
	), nil)
	m := byPath(fields)
	sec := m["services.web.secrets"]
	if !strings.Contains(sec.Value, "a") || !strings.Contains(sec.Value, "b") {
		t.Fatalf("secrets %+v", sec)
	}
	cfg := m["services.web.configs"]
	if !strings.Contains(cfg.Value, "c1") || !strings.Contains(cfg.Value, "c2") {
		t.Fatalf("configs %+v", cfg)
	}
	env := m["services.web.environment"]
	if env.Value == "" {
		t.Fatalf("environment %+v", env)
	}
	depHit := false
	for _, f := range fields {
		if strings.Contains(f.Path, "depends_on") && (strings.Contains(f.Path, "db") || strings.Contains(f.Value, "db")) {
			depHit = true
		}
	}
	if !depHit {
		var paths []string
		for _, f := range fields {
			paths = append(paths, f.Path)
		}
		t.Fatalf("depends_on missing: %s", strings.Join(paths, ","))
	}
}
