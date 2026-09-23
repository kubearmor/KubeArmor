// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package common

import (
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	kc "github.com/kubearmor/KubeArmor/KubeArmor/config"
)

// TestGetContainerIPFromPidRealNamespace exercises the real namespace-switch
// path against an actual, isolated network namespace holding a known,
// non-loopback address, rather than a mocked container. It needs root and
// CAP_NET_ADMIN/CAP_SYS_ADMIN (available on the CI runners this repo already
// requires them on for its nftables/eBPF tests), so it skips itself
// everywhere else, including a default sandboxed container.
func TestGetContainerIPFromPidRealNamespace(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root to create a network namespace")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("requires the 'ip' binary (iproute2)")
	}

	oldProcFsMount := kc.GlobalCfg.ProcFsMount
	kc.GlobalCfg.ProcFsMount = "/proc"
	t.Cleanup(func() { kc.GlobalCfg.ProcFsMount = oldProcFsMount })

	const wantIP = "10.211.99.5"
	cmd := exec.Command("sh", "-c",
		"ip link add dummy0 type dummy && ip link set dummy0 up && ip addr add "+wantIP+"/24 dev dummy0 && sleep 30")
	cmd.SysProcAttr = &syscall.SysProcAttr{Cloneflags: syscall.CLONE_NEWNET}
	if err := cmd.Start(); err != nil {
		t.Skipf("could not create an isolated network namespace: %s", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	pid := uint32(cmd.Process.Pid)

	// Give the child a moment to configure its interface before we read it.
	var got string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		got = GetContainerIPFromPid(pid)
		if got != "" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if got != wantIP {
		t.Fatalf("GetContainerIPFromPid() = %q, want %q", got, wantIP)
	}

	// Namespaces are per-thread; repeat the call to confirm the calling
	// goroutine's OS thread was correctly restored to the host namespace
	// and isn't stuck (or leaking) in the child's namespace.
	if again := GetContainerIPFromPid(pid); again != wantIP {
		t.Fatalf("GetContainerIPFromPid() on second call = %q, want %q (namespace not restored cleanly)", again, wantIP)
	}

	// A pid with no such namespace (already exited) must fail closed, not
	// return a stale or host address.
	if empty := GetContainerIPFromPid(1 << 30); empty != "" {
		t.Fatalf("GetContainerIPFromPid() for a bogus pid = %q, want empty", empty)
	}
}
