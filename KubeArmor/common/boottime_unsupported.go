// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package common

// GetBootTime is unsupported on non-Linux platforms.
func GetBootTime() string {
	return ""
}
