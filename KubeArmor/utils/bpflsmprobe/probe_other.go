// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

// Package probe checks whether the probed LSM support is available.
package probe

import "errors"

// CheckBPFLSMSupport reports that BPF-LSM support probing is unavailable on
// non-Linux platforms. It exists so that KubeArmor can be compiled on macOS and
// other non-Linux hosts for development and tooling purposes.
func CheckBPFLSMSupport() error {
	return errors.New("BPF-LSM support probing is not available on non-Linux platforms")
}
