// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/exitcode"
)

// outsideLayout creates <root>/outside.env next to the project <root>/proj.
func outsideLayout(t *testing.T, compose string) (proj, outside string) {
	t.Helper()
	root := t.TempDir()
	proj = filepath.Join(root, "proj")
	if err := os.MkdirAll(proj, 0o755); err != nil {
		t.Fatal(err)
	}
	outside = filepath.Join(root, "outside.env")
	body := "OUTSIDE_PLAIN=outsidevalue7777\nOUTSIDE_OPTS=-Xmx1g -Dy=outsideopts8888\n"
	if err := os.WriteFile(outside, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	compose = strings.ReplaceAll(compose, "{outside}", filepath.ToSlash(outside))
	if err := os.WriteFile(filepath.Join(proj, "compose.yaml"), []byte(compose), 0o644); err != nil {
		t.Fatal(err)
	}
	return proj, outside
}

var outsideValues = []string{"outsidevalue7777", "outsideopts8888"}

func TestEnvFileOutsideProjectRelativeIsWithheld(t *testing.T) {
	proj, _ := outsideLayout(t, "services:\n  api:\n    image: nginx\n    env_file: ../outside.env\n")
	assertNoneLeak(t, proj, outsideValues)
	_, out, _ := runIn(t, proj, nil, "inspect")
	if !strings.Contains(out, "OUTSIDE_PLAIN") {
		t.Errorf("key name from the outside file should stay visible:\n%s", out)
	}
	if !strings.Contains(out, "outside the project directory") {
		t.Errorf("inspect does not say why the values are withheld:\n%s", out)
	}
}

func TestEnvFileOutsideProjectAbsoluteIsWithheld(t *testing.T) {
	proj, _ := outsideLayout(t, "services:\n  api:\n    image: nginx\n    env_file: \"{outside}\"\n")
	assertNoneLeak(t, proj, outsideValues)
}

func TestEnvFileSymlinkResolvingOutsideIsWithheld(t *testing.T) {
	proj, outside := outsideLayout(t, "services:\n  api:\n    image: nginx\n    env_file: link.env\n")
	if err := os.Symlink(outside, filepath.Join(proj, "link.env")); err != nil {
		t.Skipf("symlinks unavailable here: %v", err)
	}
	assertNoneLeak(t, proj, outsideValues)
}

func TestEnvFileInsideProjectStaysReadable(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  api:\n    image: nginx\n    env_file: sub/app.env\n",
		"sub/app.env":  "APP_MODE=insidevalue5555\n",
	})
	_, out, _ := runIn(t, dir, nil, "inspect")
	if !strings.Contains(out, "insidevalue5555") {
		t.Errorf("an env_file inside the project must stay readable:\n%s", out)
	}
}

func TestEnvFileSpecialFileIsRefused(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml": "services:\n  api:\n    image: nginx\n    env_file: \"" + filepath.ToSlash(os.DevNull) + "\"\n",
	})
	for _, args := range outputCommands {
		code, _, errs := runIn(t, dir, nil, args...)
		if code != exitcode.Input {
			t.Errorf("%v: exit %d, want %d (input)", args, code, exitcode.Input)
		}
		if !strings.Contains(errs, "input-not-regular-file") {
			t.Errorf("%v: diagnostic does not name the refusal: %s", args, errs)
		}
	}
}

func TestComposeFileSpecialFileIsRefused(t *testing.T) {
	dir := t.TempDir()
	code, _, errs := runIn(t, dir, nil, "inspect", "--project-directory", dir, "-f", os.DevNull)
	if code != exitcode.Input || !strings.Contains(errs, "input-not-regular-file") {
		t.Errorf("-f %s: exit %d stderr=%s, want exit 3 input-not-regular-file", os.DevNull, code, errs)
	}
}
