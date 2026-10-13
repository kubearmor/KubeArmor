// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux && !darwin && !windows

package common

import "time"

// GetOSImage returns "" on platforms without a dedicated implementation.
func GetOSImage() string { return "" }

// GetMachineID only consults the caller-provided paths on platforms without a
// dedicated implementation.
func GetMachineID(extraPaths ...string) string { return readFirstNonEmptyFile(extraPaths...) }

// GetBootTime returns "" on platforms without a dedicated implementation.
func GetBootTime() string { return "" }

// GetSupportedLSMs returns "" on platforms without a dedicated implementation.
func GetSupportedLSMs() string { return "" }

// GetUptimeTimestamp falls back to the current time on platforms without a
// dedicated implementation (no boot-time offset available).
func GetUptimeTimestamp() float64 {
	return float64(time.Now().UnixNano()/1000) / 1000000.0
}
