// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package monitor

import (
	"strings"
	"sync"
	"testing"
	"time"

	"os"
    "path/filepath"

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

	// montor lock
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

	// montor lock
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

func TestContainerIDFromProcCgroup(t *testing.T) {
	tmp := t.TempDir()
	pid := uint32(1234)
	procPidDir := filepath.Join(tmp, "1234")
	if err := os.MkdirAll(procPidDir, 0o755); err != nil {
		t.Fatalf("failed to mkdir: %v", err)
	}

	// Test cases for different container runtimes
	testCases := []struct {
		name          string
		cgroupContent string
		expectedToken string
	}{
		{
			name:          "containerd",
			cgroupContent: "0::/system.slice/containerd.service/kubepods.slice/kubepods-burstable.slice/cri-containerd-abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789.scope\n",
			expectedToken: "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		},
		{
			name:          "cri-o",
			cgroupContent: "0::/system.slice/crio-123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234.scope\n",
			expectedToken: "123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234",
		},
		{
			name:          "docker",
			cgroupContent: "0::/docker/fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210\n",
			expectedToken: "fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(procPidDir, "cgroup"), []byte(tc.cgroupContent), 0o644); err != nil {
				t.Fatalf("write cgroup: %v", err)
			}

			// Prepare a minimal monitor with a container map
			containerMap := make(map[string]tp.Container)
			containerMap[tc.expectedToken] = tp.Container{ContainerID: tc.expectedToken}
			containerLock := new(sync.RWMutex)

			mon := &SystemMonitor{
				Containers:      &containerMap,
				ContainersLock:  &containerLock,
				cgroupCache:     make(map[uint32]cgroupCacheEntry),
				cgroupCacheLock: new(sync.RWMutex),
				cgroupBufPool: &sync.Pool{
					New: func() interface{} {
						buf := make([]byte, 4096)
						return &buf
					},
				},
			}

			// Override the procfs mount for test
			oldCfg := cfg.GlobalCfg.ProcFsMount
			cfg.GlobalCfg.ProcFsMount = tmp
			defer func() { cfg.GlobalCfg.ProcFsMount = oldCfg }()

			cid := mon.containerIDFromProcCgroup(pid)
			if cid != tc.expectedToken {
				t.Errorf("%s: expected %s, got %s", tc.name, tc.expectedToken, cid)
			}

			// Test caching - second call should use cache
			cid2 := mon.containerIDFromProcCgroup(pid)
			if cid2 != tc.expectedToken {
				t.Errorf("%s: cached result expected %s, got %s", tc.name, tc.expectedToken, cid2)
			}
		})
	}
}

func TestExtractContainerIDFromPath(t *testing.T) {
	mon := &SystemMonitor{}
	
	testCases := []struct {
		name     string
		path     string
		expected string
	}{
		{
			name:     "containerd cri format",
			path:     "/system.slice/containerd.service/kubepods.slice/cri-containerd-abc123.scope",
			expected: "abc123",
		},
		{
			name:     "crio format",
			path:     "/system.slice/crio-xyz789.scope",
			expected: "xyz789",
		},
		{
			name:     "docker format",
			path:     "/docker/def456/other",
			expected: "def456",
		},
		{
			name:     "containerd legacy",
			path:     "/containers/ghi789/tasks",
			expected: "ghi789",
		},
		{
			name:     "no match",
			path:     "/system.slice/some-other-service",
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := mon.extractContainerIDFromPath([]byte(tc.path))
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

func TestCgroupCacheExpiration(t *testing.T) {
	mon := &SystemMonitor{
		cgroupCache:     make(map[uint32]cgroupCacheEntry),
		cgroupCacheLock: new(sync.RWMutex),
	}

	// Add a cache entry with old timestamp
	pid := uint32(9999)
	mon.cgroupCacheLock.Lock()
	mon.cgroupCache[pid] = cgroupCacheEntry{
		containerID: "old-container",
		timestamp:   time.Now().Add(-10 * time.Second),
	}
	mon.cgroupCacheLock.Unlock()

	// Verify cache entry exists but is expired
	mon.cgroupCacheLock.RLock()
	entry, exists := mon.cgroupCache[pid]
	mon.cgroupCacheLock.RUnlock()

	if !exists {
		t.Fatal("cache entry should exist")
	}

	if time.Since(entry.timestamp) < 5*time.Second {
		t.Error("cache entry should be expired")
	}
}

