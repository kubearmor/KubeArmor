// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package monitor

import (
	"strings"
	"sync"
	"testing"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func TestSystemMonitor(t *testing.T) {
	StopChan = make(chan struct{})

	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// pid map
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)

	node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	node.KernelVersion = strings.TrimSuffix(node.KernelVersion, "\n")

	// load configuration
	if err := cfg.LoadConfig(); err != nil {
		t.Log("[FAIL] Failed to load configuration")
		return
	}

	// configuration
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = true

	// create logger
	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// monitor lock
	monitorLock := new(sync.RWMutex)

	// Create System Monitor
	systemMonitor := NewSystemMonitor(&node, &nodeLock, logger, &Containers, &ContainersLock, &ActiveHostPidMap, &ActivePidMapLock, &monitorLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created SystemMonitor")

	// Destroy System Monitor
	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy Feeder
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestTraceSyscallWithPod(t *testing.T) {
	StopChan = make(chan struct{})

	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// pid map
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)
	node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	node.KernelVersion = strings.TrimSuffix(node.KernelVersion, "\n")

	// configuration
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = false

	// create logger
	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// monitor lock
	monitorLock := new(sync.RWMutex)

	// Create System Monitor
	systemMonitor := NewSystemMonitor(&node, &nodeLock, logger, &Containers, &ContainersLock, &ActiveHostPidMap, &ActivePidMapLock, &monitorLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created SystemMonitor")

	// Initialize BPF
	if err := systemMonitor.InitBPF(); err != nil {
		t.Log("[FAIL] Failed to initialize BPF")

		if err := systemMonitor.DestroySystemMonitor(); err != nil {
			t.Log("[FAIL] Failed to destroy SystemMonitor")

			if err := logger.DestroyFeeder(); err != nil {
				t.Log("[FAIL] Failed to destroy logger")
				return
			}

			return
		}

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Initialized BPF (for containers)")

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

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestTraceSyscallWithHost(t *testing.T) {
	StopChan = make(chan struct{})

	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// pid map
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// node
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)
	node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	node.KernelVersion = strings.TrimSuffix(node.KernelVersion, "\n")

	// configuration
	cfg.GlobalCfg.Policy = false
	cfg.GlobalCfg.HostPolicy = true

	// create logger
	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// monitor lock
	monitorLock := new(sync.RWMutex)

	// Create System Monitor
	systemMonitor := NewSystemMonitor(&node, &nodeLock, logger, &Containers, &ContainersLock, &ActiveHostPidMap, &ActivePidMapLock, &monitorLock)
	if systemMonitor == nil {
		t.Log("[FAIL] Failed to create SystemMonitor")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Created SystemMonitor")

	// Initialize BPF
	if err := systemMonitor.InitBPF(); err != nil {
		t.Log("[FAIL] Failed to initialize BPF")

		if err := systemMonitor.DestroySystemMonitor(); err != nil {
			t.Log("[FAIL] Failed to destroy SystemMonitor")

			if err := logger.DestroyFeeder(); err != nil {
				t.Log("[FAIL] Failed to destroy logger")
				return
			}

			return
		}

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Initialized BPF (for a host)")

	// wait for a while
	time.Sleep(time.Second * 1)

	// Start to trace syscalls for host
	go systemMonitor.TraceSyscall()
	t.Log("[PASS] Started to trace syscalls")

	// wait for a while
	time.Sleep(time.Second * 1)

	// Destroy System Monitor
	if err := systemMonitor.DestroySystemMonitor(); err != nil {
		t.Log("[FAIL] Failed to destroy SystemMonitor")

		if err := logger.DestroyFeeder(); err != nil {
			t.Log("[FAIL] Failed to destroy logger")
			return
		}

		return
	}
	t.Log("[PASS] Destroyed SystemMonitor")

	// destroy logger
	if err := logger.DestroyFeeder(); err != nil {
		t.Log("[FAIL] Failed to destroy logger")
		return
	}
	t.Log("[PASS] Destroyed logger")
}

func TestWgMonitorEnsuresWorkersFinishBeforeWait(t *testing.T) {
	StopChan = make(chan struct{})

	var mon SystemMonitor
	const numWorkers = 3
	workerSignaled := make(chan struct{}, numWorkers)

	mon.WgMonitor.Add(numWorkers)
	for range numWorkers {
		go func() {
			defer mon.WgMonitor.Done()
			<-StopChan
			workerSignaled <- struct{}{}
		}()
	}

	waitReturned := make(chan struct{})
	go func() {
		mon.WgMonitor.Wait()
		close(waitReturned)
	}()

	select {
	case <-waitReturned:
		t.Fatal("WgMonitor.Wait() returned before stop signal")
	case <-time.After(50 * time.Millisecond):
	}

	close(StopChan)

	select {
	case <-waitReturned:
	case <-time.After(time.Second):
		t.Fatal("WgMonitor.Wait() did not return after stop signal")
	}

	if len(workerSignaled) != numWorkers {
		t.Fatalf("expected %d workers to finish before Wait returned, got %d", numWorkers, len(workerSignaled))
	}
}

func TestWgMonitorUpdateLogsTracked(t *testing.T) {
	StopChan = make(chan struct{})

	var mon SystemMonitor

	mon.WgMonitor.Add(1)
	go func() {
		defer mon.WgMonitor.Done()
		mon.UpdateLogs()
	}()

	waitReturned := make(chan struct{})
	go func() {
		mon.WgMonitor.Wait()
		close(waitReturned)
	}()

	select {
	case <-waitReturned:
		t.Fatal("WgMonitor.Wait() returned before stop signal")
	case <-time.After(50 * time.Millisecond):
	}

	close(StopChan)

	select {
	case <-waitReturned:
	case <-time.After(time.Second):
		t.Fatal("WgMonitor.Wait() did not return after stop signal")
	}
}
