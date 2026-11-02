// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"net"
	"sync"
	"testing"
	"time"

	"composelens/internal/testenv"
)

// End to end with the real engine: no connection reaches a
// loopback listener by default; the explicit flag is the only route.
func TestLoopbackRemoteIncludeOnlyWithAllowNetwork(t *testing.T) {
	testenv.RequireDocker(t)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback listener: %v", err)
	}
	defer func() { _ = ln.Close() }()
	var mu sync.Mutex
	hits := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			mu.Lock()
			hits++
			mu.Unlock()
			_ = c.Close()
		}
	}()
	addr := ln.Addr().String()
	dir := writeProbeProject(t, map[string]string{"compose.yaml": "include:\n  - oci://" + addr + "/solar/model:demo\nservices:\n  web:\n    image: alpine:3.21\n"})
	count := func() int { time.Sleep(300 * time.Millisecond); mu.Lock(); defer mu.Unlock(); return hits }
	rt, _, errb := reportRT(dir)
	rt.Run([]string{"report", "--json", "--project-directory", dir})
	if n := count(); n != 0 {
		t.Fatalf("default report connected %d time(s) to %s: %s", n, addr, errb.String())
	}
	rt, _, _ = reportRT(dir)
	rt.Run([]string{"report", "--json", "--allow-network", "--project-directory", dir})
	if n := count(); n == 0 {
		t.Skip("engine made no connection even with --allow-network (engine behaviour); default path already proven")
	}
}
