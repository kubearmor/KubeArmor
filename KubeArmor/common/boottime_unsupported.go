// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package common

// GetBootTime is not supported on non-Linux platforms and always returns an empty string.
func GetBootTime() string {
	return ""
}
