// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build windows

package common

import (
	"syscall"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

var (
	kernel32         = syscall.NewLazyDLL("kernel32.dll")
	procGetTickCount = kernel32.NewProc("GetTickCount64")
	uptime           time.Duration
)

func getBootTime() (time.Time, error) {
	// Call GetTickCount64 to get milliseconds elapsed since boot
	millis, _, err := procGetTickCount.Call()
	if millis == 0 && err != nil && err.Error() != "The operation completed successfully." {
		return time.Time{}, err
	}

	// Calculate boot time by subtracting uptime from current time
	uptime = time.Duration(millis) * time.Millisecond
	bootTime := time.Now().Add(-uptime)

	return bootTime, nil
}

func GetBootTime() string {
	bootTime, err := getBootTime()
	if err != nil {
		kg.Errf("Error retrieving boot time: %v\n", err)
		return ""
	}

	return bootTime.Format("2006-01-02 15:04:05")
}

// GetUptimeTimestamp Function
func GetUptimeTimestamp() float64 {
	return float64(uptime)
}
