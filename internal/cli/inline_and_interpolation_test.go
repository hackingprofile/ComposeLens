// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestInlineResourceContentUsesResourceSensitivity(t *testing.T) {
	dir := writeProject(t, map[string]string{"compose.yaml": "services: {api: {image: nginx}}\nconfigs:\n  app_secret: {content: inlineconfigleak07}\n  plain: {content: visible-settings}\nsecrets:\n  ordinary: {content: inlinesecretvalue08}\n"})
	assertNoneLeak(t, dir, []string{"inlineconfigleak07", "inlinesecretvalue08"})
	_, out, _ := runIn(t, dir, nil, "inspect", "--json")
	if !strings.Contains(out, "visible-settings") {
		t.Fatal("ordinary inline configuration withheld")
	}
}

func TestNestedAlternateAndRequiredSecretsAreWithheld(t *testing.T) {
	for _, expression := range []string{"${DB_PASSWORD:+x${DB_PASSWORD}y}", "${DB_PASSWORD:?must be ${DB_PASSWORD}}"} {
		dir := writeProject(t, map[string]string{".env": "DB_PASSWORD=" + longDBPassword + "\n", "compose.yaml": "services: {api: {image: nginx, environment: {ALT: '" + expression + "'}}}\n"})
		assertNoneLeak(t, dir, []string{longDBPassword})
	}
}

func TestInheritedShadowChainListsOnlyFieldSources(t *testing.T) {
	dir := writeProject(t, map[string]string{
		"compose.yaml":        "services: {app: {extends: {file: l1/one.yaml, service: base}}}\n",
		"l1/one.yaml":         "services: {base: {extends: {file: l2/two.yaml, service: base}, hostname: first}}\n",
		"l1/l2/two.yaml":      "services: {base: {extends: {file: l3/three.yaml, service: base}, user: second}}\n",
		"l1/l2/l3/three.yaml": "services: {base: {image: nginx, ports: ['8080:80']}}\n",
	})
	code, out, errs := runIn(t, dir, nil, "explain", "--all", "--json")
	if code != 0 {
		t.Fatalf("exit=%d %s", code, errs)
	}
	var graph struct {
		Nodes []struct {
			Target string                                 `json:"target"`
			Chain  []struct{ Role, Stage, Source string } `json:"shadowChain"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal([]byte(out), &graph); err != nil {
		t.Fatal(err)
	}
	for _, node := range graph.Nodes {
		if node.Target != "services.app.ports" {
			continue
		}
		seen := false
		for _, link := range node.Chain {
			if strings.Contains(link.Source, "one.yaml") || strings.Contains(link.Source, "two.yaml") {
				t.Errorf("file that never set ports is listed: %+v", link)
			}
			if strings.Contains(link.Source, "three.yaml") {
				seen = true
			}
		}
		if !seen {
			t.Error("actual field source absent from chain")
		}
		return
	}
	t.Fatal("ports node absent")
}
