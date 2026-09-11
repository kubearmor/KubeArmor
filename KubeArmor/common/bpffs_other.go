// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package common

// CheckOrMountBPFFs is a no-op on non-Linux platforms, where the BPF filesystem
// does not exist and KubeArmor is built only for development and tooling.
func CheckOrMountBPFFs(bpfRoot string) {}

// GetMapRoot returns the default BPF filesystem mountpoint. It is not used at
// runtime on non-Linux platforms.
func GetMapRoot() string {
	return "/sys/fs/bpf"
}
