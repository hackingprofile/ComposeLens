// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"composelens/internal/exitcode"
)

func dagProject(t *testing.T, depth int) string {
	t.Helper()
	files := map[string]string{"compose.yaml": "include: n0.yaml\nservices: {}\n"}
	for i := 0; i <= depth; i++ {
		body := ""
		if i < depth {
			body = fmt.Sprintf("include: [n%d.yaml, n%d.yaml]\n", i+1, i+1)
		}
		files[fmt.Sprintf("n%d.yaml", i)] = body + "services: {web: {image: alpine:3.21}}\n"
	}
	return writeProbeProject(t, files)
}

// A repeated-include DAG cannot defeat the work bounds. Total
// include expansion per invocation is bounded with a typed refusal; a small
// DAG within the bound still works and keeps include ordering.
func TestRepeatedIncludeDAGIsBounded(t *testing.T) {
	type res struct {
		code     int
		out, err string
	}
	runWithin := func(dir string) (res, bool) {
		ch := make(chan res, 1)
		go func() {
			rt, out, errb := reportRT(dir)
			code := rt.Run([]string{"inspect", "--json", "--project-directory", dir})
			ch <- res{code, out.String(), errb.String()}
		}()
		select {
		case r := <-ch:
			return r, true
		case <-time.After(10 * time.Second):
			return res{}, false
		}
	}
	for _, depth := range []int{8, 16} {
		r, ok := runWithin(dagProject(t, depth))
		if !ok {
			t.Fatalf("dag-%d: still running after 10 s", depth)
		}
		if r.code != exitcode.Input || r.out != "" || !strings.Contains(r.err, "include-expansion-limit") {
			t.Errorf("dag-%d: code=%d stdout=%d err=%.200s", depth, r.code, len(r.out), r.err)
		}
	}
	r, ok := runWithin(dagProject(t, 4))
	if !ok || r.code != exitcode.OK {
		t.Fatalf("dag-4 within the bound: ok=%v code=%d err=%s", ok, r.code, r.err)
	}
}
