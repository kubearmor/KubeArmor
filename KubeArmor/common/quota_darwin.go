// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package common

import (
	"runtime/debug"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"golang.org/x/sys/unix"
)

// Platform default resource quota values for macOS
const (
	DefaultMaxMemoryMB = 512 // Default 512MB RAM ceiling on macOS
	DefaultNiceLevel   = 1   // Default nice level 1 (background friendliness for developer machines)
)

// ApplyResourceQuotas enforces memory limits and CPU scheduling priority on macOS (Darwin).
func ApplyResourceQuotas(maxMemoryMB int, niceLevel int) {
	if maxMemoryMB > 0 {
		memBytes := int64(maxMemoryMB) * 1024 * 1024
		debug.SetMemoryLimit(memBytes)
		kg.Printf("Enforced macOS Go runtime memory limit: %d MB", maxMemoryMB)

		// Set data segment resource limit via RLIMIT_DATA
		var rlim unix.Rlimit
		rlim.Cur = uint64(memBytes)
		rlim.Max = uint64(memBytes * 2)
		if err := unix.Setrlimit(unix.RLIMIT_DATA, &rlim); err != nil {
			kg.Warnf("Could not set RLIMIT_DATA on macOS: %v", err)
		}
	}

	if niceLevel > 0 {
		if err := unix.Setpriority(unix.PRIO_PROCESS, 0, niceLevel); err != nil {
			kg.Warnf("Could not set process nice priority to %d on macOS: %v", niceLevel, err)
		} else {
			kg.Printf("Set macOS process scheduling nice level to %d", niceLevel)
		}
	}
}
