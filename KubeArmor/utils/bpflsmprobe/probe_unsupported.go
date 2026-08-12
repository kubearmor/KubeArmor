// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

// Package probe checks whether the probed LSM support is available.
package probe

import "fmt"

// CheckBPFLSMSupport is unsupported on non-Linux platforms.
func CheckBPFLSMSupport() error {
	return fmt.Errorf("BPF LSM probing is only supported on Linux")
}
