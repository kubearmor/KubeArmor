package monitor

import (
	"os"
	"sync"
	"testing"
	"time"

	fd "github.com/accuknox/KubeArmor/KubeArmor/feeder"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

func TestSystemMonitor(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// container id -> pid
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// container id -> host pid
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActiveHostPidMapLock := &sync.Mutex{}

	// Create Feeder
	logFeeder := fd.NewFeeder("32767", "none")
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	// Create System Monitor

	systemMonitor := NewSystemMonitor(logFeeder, &Containers, &ContainersLock, &ActivePidMap, &ActivePidMapLock, &ActiveHostPidMap, &ActiveHostPidMapLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")
		return
	}

	t.Log("[PASS] Created SystemMonitor")

	// Destroy System Monitor

	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")
	}

	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}

func TestTraceSyscall(t *testing.T) {
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := &sync.Mutex{}

	// container id -> pid
	ActivePidMap := map[string]tp.PidMap{}
	ActivePidMapLock := &sync.Mutex{}

	// container id -> host pid
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActiveHostPidMapLock := &sync.Mutex{}

	// Create Feeder
	logFeeder := fd.NewFeeder("32767", "none")
	if logFeeder == nil {
		t.Log("[FAIL] Failed to create Feeder")
		return
	}

	// Create System Monitor

	systemMonitor := NewSystemMonitor(logFeeder, &Containers, &ContainersLock, &ActivePidMap, &ActivePidMapLock, &ActiveHostPidMap, &ActiveHostPidMapLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")
		return
	}

	t.Log("[PASS] Created SystemMonitor")

	// Get the current directory

	dir := os.Getenv("PWD")

	t.Logf("[PASS] Got the current directory (%s)", dir)

	// Initialize BPF

	if err := systemMonitor.InitBPF(dir + "/.."); err != nil {
		t.Errorf("[FAIL] Failed to initialize BPF (%s)", err.Error())
		return
	}

	t.Logf("[PASS] Initialized BPF (Dir: %s/..)", dir)

	// wait for a while

	time.Sleep(time.Second * 1)

	// Start to trace syscalls

	go systemMonitor.TraceSyscall()

	t.Log("[PASS] Started to trace syscalls")

	// wait for a while

	time.Sleep(time.Second * 1)

	// Destroy System Monitor

	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")
	}

	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy Feeder
	if err := logFeeder.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy Feeder")
		return
	}

	t.Log("[PASS] Destroyed Feeder")
}
