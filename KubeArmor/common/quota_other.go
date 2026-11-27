// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !darwin

package common

import (
	"runtime/debug"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// Platform default resource quota values for Linux / other systems (unbounded by default)
const (
	DefaultMaxMemoryMB = 0
	DefaultNiceLevel   = 0
)

// ApplyResourceQuotas sets Go runtime memory limits on non-Darwin platforms if explicitly configured.
func ApplyResourceQuotas(maxMemoryMB int, niceLevel int) {
	if maxMemoryMB > 0 {
		memBytes := int64(maxMemoryMB) * 1024 * 1024
		debug.SetMemoryLimit(memBytes)
		kg.Printf("Enforced Go runtime memory limit: %d MB", maxMemoryMB)
	}
}
