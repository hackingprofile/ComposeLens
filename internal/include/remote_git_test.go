// SPDX-License-Identifier: Apache-2.0

package include

import "testing"

func TestIsRemoteRecognizesSchemelessGitAddresses(t *testing.T) {
	remote := []string{
		"github.com/docker/awesome-compose.git#master:nginx-golang",
		"github.com/docker/awesome-compose.git",
		"gitlab.example.org/team/repo.git#v1",
		"git@github.com:docker/awesome-compose.git",
		"https://github.com/docker/awesome-compose.git",
		"oci://registry.example/compose:1",
	}
	for _, p := range remote {
		if !IsRemote(p) {
			t.Errorf("IsRemote(%q) = false, want true", p)
		}
	}
	local := []string{
		"base.yaml", "sub/base.yaml", "./local.git/compose.yaml", "../shared/compose.yaml",
		"compose.git.yaml", "C:/work/repo.git/compose.yaml", "/srv/repo.git/compose.yaml", "sub.d/compose.yaml",
	}
	for _, p := range local {
		if IsRemote(p) {
			t.Errorf("IsRemote(%q) = true, want false", p)
		}
	}
}
