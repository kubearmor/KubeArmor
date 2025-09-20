package monitor

import (
	"os"
	"path/filepath"
	"testing"
	"sync"

	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestContainerIDFromProcCgroup(t *testing.T) {
	tmp := t.TempDir()
	pid := uint32(1234)
	procPidDir := filepath.Join(tmp, "1234")
	if err := os.MkdirAll(procPidDir, 0o755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}
	// Simulate systemd cgroup path with containerd: cri-containerd-<id>.scope
	cidToken := "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
	cgroupContent := "0::/system.slice/containerd.service/kubepods.slice/kubepods-burstable.slice/cri-containerd-" + cidToken + ".scope\n"
	if err := os.WriteFile(filepath.Join(procPidDir, "cgroup"), []byte(cgroupContent), 0o644); err != nil {
		t.Fatalf("write cgroup: %v", err)
	}

	// Prepare a minimal monitor with a container map that includes the token
	m := map[string]tp.Container{
		cidToken: { ContainerID: cidToken },
	}
	mon := &SystemMonitor{}
	mon.Containers = &m
	lock := new(sync.RWMutex)
	mon.ContainersLock = &lock

	oldProc := cfg.GlobalCfg.ProcFsMount
	cfg.GlobalCfg.ProcFsMount = tmp
	t.Cleanup(func() {
		cfg.GlobalCfg.ProcFsMount = oldProc
	})

	got := mon.containerIDFromProcCgroup(pid)
	if got != cidToken {
		t.Fatalf("expected %s, got %s", cidToken, got)
	}
}