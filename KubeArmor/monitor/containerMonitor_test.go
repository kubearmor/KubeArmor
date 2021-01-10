package monitor

import (
	"os"
	"sync"
	"testing"

	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func TestContainerMonitor(t *testing.T) {
	// == //

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// ActivePidMap
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// == //

	// Create Container Monitor

	t.Log("[INFO] Create ContainerMonitor (file:/tmp/kubearmor-system.log)")

	containerMonitor := NewContainerMonitor("file:/tmp/kubearmor-system.log", Containers, ContainersLock, ActivePidMap, ActivePidMapLock)
	if containerMonitor == nil {
		t.Log("[FAIL] Failed to create ContainerMonitor")
	}

	t.Log("[PASS] Created ContainerMonitor")

	// == //

	// Destroy Container Monitor

	t.Log("[INFO] Destroy ContainerMonitor")

	if err := containerMonitor.DestroyContainerMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy ContainerMonitor")
	}

	t.Log("[PASS] Destroyed ContainerMonitor")

	// == //

	// Remove system log

	t.Log("[INFO] Remove /tmp/kubearmor-system.log")

	if err := os.Remove("/tmp/kubearmor-system.log"); err != nil {
		t.Errorf("[FAIL] Failed to remove /tmp/kubearmor-system.log (%s)", err.Error())
		return
	}

	t.Log("[PASS] Removed /tmp/kubearmor-system.log")

	// == //
}
