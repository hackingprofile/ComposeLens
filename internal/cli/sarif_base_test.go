// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func selectedBaseProject(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	for name, body := range map[string]string{
		"projects/app/compose.yaml": "services:\n  web:\n    image: alpine:3.21\n    environment:\n      PASSWORD: solar-secretvalue\n",
		"elsewhere/compose.yaml":    "services:\n  web:\n    image: alpine:3.21\n    environment:\n      PASSWORD: solar-secretvalue\n",
		"projects/app/.placeholder": "",
	} {
		p := filepath.Join(root, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

// SARIF URIs are relative to the selected project directory and
// GitHub annotations to GITHUB_WORKSPACE (or the project when it is unset).
// A file outside that base gets no location; it is never reduced to its
// basename.
func TestSARIFAndAnnotationsUseTheSelectedBase(t *testing.T) {
	root := selectedBaseProject(t)
	file := filepath.Join(root, "projects", "app", "compose.yaml")

	t.Setenv("GITHUB_WORKSPACE", root)
	rt, out, errb := reportRT(root)
	rt.Run([]string{"check", "--sarif", "--project-directory", root, "-f", file})
	if uri, line := sarifURILine(t, out.String(), "web:PASSWORD"); uri != "projects/app/compose.yaml" || line != 5 {
		t.Errorf("SARIF uri=%q line=%d err=%s", uri, line, errb.String())
	}
	rt, out, _ = reportRT(root)
	rt.Run([]string{"check", "--github", "--project-directory", root, "-f", file})
	if !strings.Contains(out.String(), "file=projects/app/compose.yaml,line=5") {
		t.Errorf("annotation: %s", out.String())
	}

	// Project is the app folder; the workspace is the repository root.
	app := filepath.Join(root, "projects", "app")
	rt, out, _ = reportRT(app)
	rt.Run([]string{"check", "--sarif", "--project-directory", app})
	if uri, _ := sarifURILine(t, out.String(), "web:PASSWORD"); uri != "compose.yaml" {
		t.Errorf("project-relative SARIF uri=%q", uri)
	}
	rt, out, _ = reportRT(app)
	rt.Run([]string{"check", "--github", "--project-directory", app})
	if !strings.Contains(out.String(), "file=projects/app/compose.yaml,line=5") {
		t.Errorf("workspace-relative annotation: %s", out.String())
	}

	// Outside policy: a file outside the project (SARIF) or the workspace
	// (annotation) has no physical location, never a guessed basename.
	other := filepath.Join(root, "elsewhere", "compose.yaml")
	rt, out, _ = reportRT(app)
	rt.Run([]string{"check", "--sarif", "--project-directory", app, "-f", other})
	if strings.Contains(out.String(), `"uri"`) {
		t.Errorf("file outside the project got a SARIF uri: %s", out.String())
	}
	t.Setenv("GITHUB_WORKSPACE", app)
	rt, out, _ = reportRT(app)
	rt.Run([]string{"check", "--github", "--project-directory", app, "-f", other})
	if strings.Contains(out.String(), "file=") {
		t.Errorf("file outside the workspace got an annotation file: %s", out.String())
	}
}
