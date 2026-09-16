// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package monitor

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type fakeLink struct {
	closeErr error
	closed   bool
	mu       sync.Mutex
}

func (f *fakeLink) Close() error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.closed = true
	return f.closeErr
}

func consumeReplay(replay <-chan []byte, syscall chan<- []byte) {
	for data := range replay {
		for range 10 {
			select {
			case syscall <- data:
				goto next
			default:
			}
		}
	next:
	}
}

var (
	loadConfigOnce sync.Once
	loadConfigErr  error
)

func mustLoadConfig(t *testing.T) {
	t.Helper()
	loadConfigOnce.Do(func() {
		loadConfigErr = cfg.LoadConfig()
	})
	if loadConfigErr != nil {
		t.Fatalf("could not load config: %v", loadConfigErr)
	}
}

func TestSystemMonitor(t *testing.T) {
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
	mustLoadConfig(t)

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

func TestDestroySystemMonitor_AllProbesClosedOnError(t *testing.T) {
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)
	node.KernelVersion = strings.TrimSuffix(
		kl.GetCommandOutputWithoutErr("uname", []string{"-r"}), "\n",
	)

	mustLoadConfig(t)

	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Skip("could not create feeder")
	}
	defer logger.DestroyFeeder()

	monitorLock := new(sync.RWMutex)
	mon := NewSystemMonitor(
		&node, &nodeLock, logger,
		&Containers, &ContainersLock,
		&ActiveHostPidMap, &ActivePidMapLock,
		&monitorLock,
	)
	if mon == nil {
		t.Skip("could not create SystemMonitor")
	}

	probeA := &fakeLink{closeErr: fmt.Errorf("probe_a failed")}
	probeB := &fakeLink{}
	mon.Probes = map[string]linkCloser{
		"probe_a": probeA,
		"probe_b": probeB,
	}

	mon.ContextChan = make(chan ContextCombined, 1)

	_ = mon.DestroySystemMonitor()

	if !probeA.closed {
		t.Error("probe_a was not closed")
	}
	if !probeB.closed {
		t.Error("probe_b was not closed: early return leaked this probe")
	}
}

func TestDestroySystemMonitor_JoinsProbeErrors(t *testing.T) {
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)
	node := tp.Node{}
	nodeLock := new(sync.RWMutex)
	node.KernelVersion = strings.TrimSuffix(
		kl.GetCommandOutputWithoutErr("uname", []string{"-r"}), "\n",
	)

	mustLoadConfig(t)

	logger := feeder.NewFeeder(&node, &nodeLock)
	if logger == nil {
		t.Skip("could not create feeder")
	}
	defer logger.DestroyFeeder()

	monitorLock := new(sync.RWMutex)
	mon := NewSystemMonitor(
		&node, &nodeLock, logger,
		&Containers, &ContainersLock,
		&ActiveHostPidMap, &ActivePidMapLock,
		&monitorLock,
	)
	if mon == nil {
		t.Skip("could not create SystemMonitor")
	}

	mon.Probes = map[string]linkCloser{
		"probe_a": &fakeLink{closeErr: fmt.Errorf("probe_a close failed")},
		"probe_b": &fakeLink{closeErr: fmt.Errorf("probe_b close failed")},
	}
	mon.ContextChan = make(chan ContextCombined, 1)

	err := mon.DestroySystemMonitor()
	if err == nil {
		t.Fatal("expected joined error, got nil")
	}
	if !strings.Contains(err.Error(), "probe_a close failed") {
		t.Errorf("expected probe_a error in result, got: %s", err.Error())
	}
	if !strings.Contains(err.Error(), "probe_b close failed") {
		t.Errorf("expected probe_b error in result, got: %s", err.Error())
	}
}

func TestReplayChannel_GoroutineExitsOnClose(t *testing.T) {
	replay := make(chan []byte, 4)
	syscall := make(chan []byte, 16)
	done := make(chan struct{})

	go func() {
		defer close(done)
		consumeReplay(replay, syscall)
	}()

	close(replay)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Error("consumeReplay did not exit after replay channel was closed: goroutine leak")
	}
}

func TestConsumeReplay_ForwardsDataToSyscallChannel(t *testing.T) {
	replay := make(chan []byte, 4)
	syscall := make(chan []byte, 16)

	replay <- []byte("event1")
	replay <- []byte("event2")
	close(replay)

	consumeReplay(replay, syscall)

	if len(syscall) != 2 {
		t.Errorf("expected 2 events forwarded, got %d", len(syscall))
	}
}
