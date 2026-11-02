// SPDX-License-Identifier: Apache-2.0

package adoption

// Case is one documented adoption invocation (docs/examples.md).
type Case struct {
	ID      string
	Args    []string
	Exit    int
	Contain string
}

// Cases is the local runner table. CI does not execute these; go test does.
func Cases() []Case {
	return []Case{
		{ID: "M1", Args: []string{"doctor", "--json", "--project-directory", "examples/monorepo/apps/web"}, Exit: 0, Contain: `"schema": "composelens.doctor.v0"`},
		{ID: "M2", Args: []string{"inspect", "--json", "--project-directory", "examples/monorepo/apps/web"}, Exit: 0, Contain: `"name": "web"`},
		{ID: "M3", Args: []string{"check", "--json", "--project-directory", "examples/monorepo/apps/web"}, Exit: 0, Contain: `"total": 0`},
		{ID: "M4", Args: []string{"inspect", "--json", "--project-directory", "examples/monorepo", "--file", "examples/monorepo/apps/web/compose.yaml", "--file", "examples/monorepo/overlays/shared.yaml"}, Exit: 0, Contain: "SHARED_FLAG"},
		{ID: "M5", Args: []string{"check", "--json", "--project-directory", "examples/monorepo/apps/api"}, Exit: 0, Contain: `"total": 0`},
		{ID: "M6", Args: []string{"inspect", "--json", "--profile", "debug", "--project-directory", "examples/monorepo/apps/api"}, Exit: 0, Contain: `"name": "api"`},
		{ID: "P1", Args: []string{"inspect", "--json", "--project-directory", "examples/multi-project/shop"}, Exit: 0, Contain: `"name": "shop"`},
		{ID: "P2", Args: []string{"check", "--json", "--project-directory", "examples/multi-project/shop"}, Exit: 0, Contain: `"total": 0`},
		{ID: "P3", Args: []string{"inspect", "--json", "--project-directory", "examples/multi-project/billing"}, Exit: 0, Contain: `"name": "billing"`},
		{ID: "P4", Args: []string{"check", "--json", "--project-directory", "examples/multi-project/billing"}, Exit: 0, Contain: `"total": 0`},
	}
}
