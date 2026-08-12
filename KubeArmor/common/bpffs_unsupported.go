// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package common

import "sync"

var (
	defaultBPFFsPath  = "/sys/fs/bpf"
	fallbackBPFFsPath = "/run/kubearmor/bpffs"
	mapRoot           = defaultBPFFsPath
	lockedDown        = false
	once              sync.Once
)

// CheckOrMountBPFFs is a no-op on non-Linux platforms.
func CheckOrMountBPFFs(string) {}

func lockDown() {
	lockedDown = true
}

func setMapRoot(path string) {
	if lockedDown {
		panic("setMapRoot() call after MapRoot was read")
	}
	mapRoot = path
}

// GetMapRoot returns the configured BPF map root path.
func GetMapRoot() string {
	once.Do(lockDown)
	return mapRoot
}
