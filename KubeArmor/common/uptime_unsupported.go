// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package common

import "time"

// GetUptimeTimestamp returns the current timestamp on platforms without /proc/uptime.
func GetUptimeTimestamp() float64 {
	return float64(time.Now().UTC().UnixMicro()) / 1000000.0
}
