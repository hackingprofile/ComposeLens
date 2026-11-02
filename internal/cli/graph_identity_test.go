// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"composelens/internal/report"
)

const identityNavCompose = `name: demo-project
services:
  app:
    image: alpine
    command: echo hi
  app2:
    image: alpine
  app.worker:
    image: alpine
  name:
    image: alpine
`

func identityProject(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(identityNavCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

const phantomNameCompose = `name: demo-project
services:
  app:
    image: alpine
`

func TestExplainAllOmitsProjectNameWithoutCollidingService(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(phantomNameCompose), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("explain --all code=%d err=%s", code, errb.String())
	}
	var graph struct {
		Counts struct {
			Services int `json:"services"`
		} `json:"counts"`
		Nodes []struct {
			Target string `json:"target"`
			Kind   string `json:"kind"`
			State  string `json:"state"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	if _, ok := nodeKind(graph.Nodes, "name"); ok {
		t.Fatal("project name: became a graph target")
	}
	n, ok := nodeKind(graph.Nodes, "app")
	if !ok || !strings.HasPrefix(n, "service/") || strings.HasSuffix(n, "/absent") {
		t.Fatalf("app node %q", n)
	}
	if graph.Counts.Services != 1 {
		t.Fatalf("services=%d", graph.Counts.Services)
	}
}

func nodeKind(nodes []struct {
	Target string `json:"target"`
	Kind   string `json:"kind"`
	State  string `json:"state"`
}, target string) (string, bool) {
	for _, n := range nodes {
		if n.Target == target {
			return n.Kind + "/" + n.State, true
		}
	}
	return "", false
}

func TestExplainAllOmitsPhantomProjectName(t *testing.T) {
	dir := identityProject(t)
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("explain --all code=%d err=%s", code, errb.String())
	}
	var graph struct {
		Counts struct {
			Services int `json:"services"`
			Total    int `json:"total"`
		} `json:"counts"`
		Nodes []struct {
			Target string `json:"target"`
			Kind   string `json:"kind"`
			State  string `json:"state"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	byTarget := map[string]string{}
	for _, n := range graph.Nodes {
		byTarget[n.Target] = n.Kind + "/" + n.State
		if n.Target == "name" && n.Kind == "service" && n.State == "absent" {
			t.Fatal("phantom project name node")
		}
	}
	for _, svc := range []string{"app", "app2", "app.worker", "name"} {
		if !strings.HasPrefix(byTarget[svc], "service/") || strings.HasSuffix(byTarget[svc], "/absent") {
			t.Fatalf("%s node %q in %+v", svc, byTarget[svc], byTarget)
		}
	}
	if _, ok := byTarget["services.app.command"]; !ok {
		t.Fatal("app command field missing")
	}
	if _, ok := byTarget["services.app2.command"]; ok {
		t.Fatal("app2 has no command field")
	}
	if graph.Counts.Services != 4 {
		t.Fatalf("services=%d", graph.Counts.Services)
	}
}

func TestExplainAllReservedPrefixAndDottedField(t *testing.T) {
	dir := t.TempDir()
	reserved := "services:\n  web:\n    image: alpine:web\n  \"services.web\":\n    image: alpine:reserved\n    profiles: [off]\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(reserved), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("reserved code=%d err=%s", code, errb.String())
	}
	var graph struct {
		Nodes []struct {
			Target    string `json:"target"`
			Kind      string `json:"kind"`
			State     string `json:"state"`
			Effective string `json:"effective"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	by := map[string]string{}
	for _, n := range graph.Nodes {
		by[n.Target] = n.Kind + "/" + n.Effective
	}
	if !strings.HasPrefix(by["services.web"], "service/") {
		t.Fatalf("services.web %q in %+v", by["services.web"], by)
	}
	if !strings.HasPrefix(by["web"], "service/") {
		t.Fatalf("web %q", by["web"])
	}
	if by["services.web.image"] != "field/alpine:web" {
		t.Fatalf("web image %q", by["services.web.image"])
	}

	dir2 := t.TempDir()
	dotted := "services:\n  web:\n    image: alpine:web\n  \"web.image\":\n    image: alpine:dotted\n"
	if err := os.WriteFile(filepath.Join(dir2, "compose.yaml"), []byte(dotted), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	rt.Cwd = dir2
	code = rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir2})
	if code != 0 {
		t.Fatalf("dotted code=%d err=%s", code, errb.String())
	}
	graph.Nodes = nil
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	by = map[string]string{}
	for _, n := range graph.Nodes {
		by[n.Target] = n.Kind + "/" + n.Effective
	}
	if by["services.web.image"] != "field/alpine:web" {
		t.Fatalf("web field %q in %+v", by["services.web.image"], by)
	}
	if !strings.HasPrefix(by["web.image"], "service/") {
		t.Fatalf("dotted service %q", by["web.image"])
	}
	if by["services.web.image.image"] != "field/alpine:dotted" {
		t.Fatalf("dotted field %q", by["services.web.image.image"])
	}
}

func TestExplainAllCombinedCollisionAndReservedEnv(t *testing.T) {
	dir := t.TempDir()
	collision := "services:\n  web:\n    image: alpine:3.21.3\n  \"services.web.image\":\n    image: alpine:3.19\n"
	if err := os.WriteFile(filepath.Join(dir, "compose.yaml"), []byte(collision), 0o644); err != nil {
		t.Fatal(err)
	}
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("collision code=%d err=%s", code, errb.String())
	}
	var graph struct {
		Counts struct {
			Services int `json:"services"`
			Fields   int `json:"fields"`
		} `json:"counts"`
		Nodes []struct {
			Target    string `json:"target"`
			Kind      string `json:"kind"`
			State     string `json:"state"`
			Effective string `json:"effective"`
		} `json:"nodes"`
	}
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	if graph.Counts.Services != 2 {
		t.Fatalf("services=%d", graph.Counts.Services)
	}
	var gotField, gotSvc bool
	for _, n := range graph.Nodes {
		if n.State == "absent" {
			t.Fatalf("absent node %+v", n)
		}
		if n.Target == "services.web.image" && n.Kind == "field" && n.Effective == "alpine:3.21.3" {
			gotField = true
		}
		if n.Target == "services.web.image" && n.Kind == "service" {
			gotSvc = true
		}
	}
	if !gotField || !gotSvc {
		t.Fatalf("collision nodes field=%v svc=%v %+v", gotField, gotSvc, graph.Nodes)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"explain", "services.web.image", "--json", "--project-directory", dir}); code != 0 {
		t.Fatalf("cli collision code=%d err=%s", code, errb.String())
	}
	var acc struct {
		State  string `json:"state"`
		Reason string `json:"reason"`
		Kind   string `json:"kind"`
	}
	if err := json.Unmarshal(out.Bytes(), &acc); err != nil {
		t.Fatal(err)
	}
	if acc.State != "absent" || !strings.Contains(acc.Reason, "more than one entity") {
		t.Fatalf("cli collision %+v", acc)
	}

	dir2 := t.TempDir()
	env := "services:\n  \"services.web\":\n    image: alpine:3.21.3\n    environment:\n      APP_ENV: demonstration\n"
	if err := os.WriteFile(filepath.Join(dir2, "compose.yaml"), []byte(env), 0o644); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	errb.Reset()
	rt.Cwd = dir2
	if code := rt.Run([]string{"explain", "services.web:APP_ENV", "--json", "--project-directory", dir2}); code != 0 {
		t.Fatalf("env code=%d err=%s", code, errb.String())
	}
	var envAcc explainReport
	if err := json.Unmarshal(out.Bytes(), &envAcc); err != nil {
		t.Fatal(err)
	}
	if envAcc.Target.Kind != "env" || envAcc.Target.Service != "services.web" || envAcc.Target.Key != "APP_ENV" {
		t.Fatalf("env target %+v", envAcc.Target)
	}
	if envAcc.Effective.Text == nil || *envAcc.Effective.Text != "demonstration" {
		t.Fatalf("env effective %+v", envAcc.Effective)
	}
	out.Reset()
	errb.Reset()
	if code := rt.Run([]string{"explain", "--all", "--json", "--project-directory", dir2}); code != 0 {
		t.Fatalf("env graph code=%d err=%s", code, errb.String())
	}
	graph.Nodes = nil
	if err := json.Unmarshal(out.Bytes(), &graph); err != nil {
		t.Fatal(err)
	}
	var envNode, svcNode bool
	for _, n := range graph.Nodes {
		if n.Target == "services.web:APP_ENV" && n.Kind == "env" && n.Effective == "demonstration" {
			envNode = true
		}
		if n.Target == "services.web" && n.Kind == "service" {
			svcNode = true
		}
		if n.Kind == "service" && n.State == "absent" {
			t.Fatalf("phantom service %+v", n)
		}
	}
	if !envNode || !svcNode {
		t.Fatalf("env graph env=%v svc=%v %+v", envNode, svcNode, graph.Nodes)
	}
}

func TestReportHTMLIdentityCountsAndCSP(t *testing.T) {
	dir := identityProject(t)
	rt, out, errb := reportRT(dir)
	code := rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("report --html code=%d err=%s", code, errb.String())
	}
	page1 := append([]byte(nil), out.Bytes()...)
	out.Reset()
	errb.Reset()
	code = rt.Run([]string{"report", "--html", "--project-directory", dir})
	if code != 0 {
		t.Fatalf("second html code=%d err=%s", code, errb.String())
	}
	if string(page1) != out.String() {
		t.Fatal("HTML render is not byte-identical")
	}
	island, err := report.DataIslandJSON(page1)
	if err != nil {
		t.Fatal(err)
	}
	var pkg report.Package
	if err := json.Unmarshal(island, &pkg); err != nil {
		t.Fatal(err)
	}
	if len(pkg.Source.Services) != 4 || pkg.Graph.Counts.Services != 4 {
		t.Fatalf("overview services=%d graph services=%d", len(pkg.Source.Services), pkg.Graph.Counts.Services)
	}
	for _, n := range pkg.Graph.Nodes {
		if n.Target == "name" && n.Kind == "service" && n.State == "absent" {
			t.Fatal("phantom name in HTML island")
		}
	}
	if !strings.Contains(string(page1), `http-equiv="Content-Security-Policy"`) {
		t.Fatal("CSP missing")
	}
	if strings.Contains(strings.ToLower(string(page1)), "unsafe-inline") {
		t.Fatal("CSP stripped or admits unsafe-inline")
	}
	verifyHTMLCSP(t, page1)
}

func verifyHTMLCSP(t *testing.T, page []byte) {
	t.Helper()
	s := string(page)
	pre := `content="`
	i := strings.Index(s, `http-equiv="Content-Security-Policy"`)
	if i < 0 {
		t.Fatal("no CSP meta")
	}
	start := strings.Index(s[i:], pre)
	if start < 0 {
		t.Fatal("no CSP content")
	}
	start = i + start + len(pre)
	end := strings.Index(s[start:], `"`)
	if end < 0 {
		t.Fatal("unterminated CSP")
	}
	csp := s[start : start+end]
	style := sliceBetween(s, "<style>", "</style>")
	scripts := strings.Split(s, "<script>")
	if len(scripts) < 2 {
		t.Fatal("missing boot script")
	}
	boot := strings.SplitN(scripts[len(scripts)-1], "</script>", 2)[0]
	island, err := report.DataIslandJSON(page)
	if err != nil {
		t.Fatal(err)
	}
	styleHash := "sha256-" + base64.StdEncoding.EncodeToString(sha256sum(style))
	bootHash := "sha256-" + base64.StdEncoding.EncodeToString(sha256sum(boot))
	islandHash := "sha256-" + base64.StdEncoding.EncodeToString(sha256sum(string(island)))
	if !strings.Contains(csp, styleHash) || !strings.Contains(csp, bootHash) || !strings.Contains(csp, islandHash) {
		t.Fatalf("CSP hash mismatch style=%s boot=%s island=%s csp=%s", styleHash, bootHash, islandHash, csp)
	}
}

func sha256sum(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

func sliceBetween(s, a, b string) string {
	i := strings.Index(s, a)
	if i < 0 {
		return ""
	}
	i += len(a)
	j := strings.Index(s[i:], b)
	if j < 0 {
		return ""
	}
	return s[i : i+j]
}
