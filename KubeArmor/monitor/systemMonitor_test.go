// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

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
	// Set up Test Data

	// containers
	Containers := map[string]tp.Container{}
	ContainersLock := new(sync.RWMutex)

	// container id -> (host) pid
	ActivePidMap := map[string]tp.PidMap{}
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// host pid
	ActiveHostMap := map[uint32]tp.PidMap{}
	ActiveHostMapLock := new(sync.RWMutex)

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	node.KernelVersion = strings.TrimSuffix(node.KernelVersion, "\n")
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = true

	// create logger
	logger := feeder.NewFeeder("Default", &node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// Create System Monitor
	systemMonitor := NewSystemMonitor(node, logger, &Containers, &ContainersLock,
		&ActivePidMap, &ActiveHostPidMap, &ActivePidMapLock, &ActiveHostMap, &ActiveHostMapLock)
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

	// container id -> (host) pid
	ActivePidMap := map[string]tp.PidMap{}
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// host pid
	ActiveHostMap := map[uint32]tp.PidMap{}
	ActiveHostMapLock := new(sync.RWMutex)

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	node.KernelVersion = strings.TrimSuffix(node.KernelVersion, "\n")
	cfg.GlobalCfg.Policy = true
	cfg.GlobalCfg.HostPolicy = false

	// create logger
	logger := feeder.NewFeeder("Default", &node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// Create System Monitor
	systemMonitor := NewSystemMonitor(node, logger, &Containers, &ContainersLock,
		&ActivePidMap, &ActiveHostPidMap, &ActivePidMapLock, &ActiveHostMap, &ActiveHostMapLock)
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
		t.Errorf("[FAIL] Failed to initialize BPF (%s)", err.Error())

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
	t.Logf("[PASS] Initialized BPF (for containers)")

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

	// container id -> (host) pid
	ActivePidMap := map[string]tp.PidMap{}
	ActiveHostPidMap := map[string]tp.PidMap{}
	ActivePidMapLock := new(sync.RWMutex)

	// host pid
	ActiveHostMap := map[uint32]tp.PidMap{}
	ActiveHostMapLock := new(sync.RWMutex)

	// node
	node := tp.Node{}
	node.NodeName = "nodeName"
	node.KernelVersion = kl.GetCommandOutputWithoutErr("uname", []string{"-r"})
	node.KernelVersion = strings.TrimSuffix(node.KernelVersion, "\n")
	cfg.GlobalCfg.Policy = false
	cfg.GlobalCfg.HostPolicy = true

	// create logger
	logger := feeder.NewFeeder("Default", &node, "32767", "none")
	if logger == nil {
		t.Log("[FAIL] Failed to create logger")
		return
	}
	t.Log("[PASS] Created logger")

	// Create System Monitor
	systemMonitor := NewSystemMonitor(node, logger, &Containers, &ContainersLock,
		&ActivePidMap, &ActiveHostPidMap, &ActivePidMapLock, &ActiveHostMap, &ActiveHostMapLock)
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
		t.Errorf("[FAIL] Failed to initialize BPF (%s)", err.Error())

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
	t.Logf("[PASS] Initialized BPF (for a host)")

	// wait for a while
	time.Sleep(time.Second * 1)

	// Start to trace syscalls for host
	go systemMonitor.TraceHostSyscall()
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
