// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

package common

import (
	"time"

	"golang.org/x/sys/unix"
)

// GetBootTime returns the current boot time on Linux.
// credits: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/util/boottime_util_linux.go
func GetBootTime() string {
	currentTime := time.Now()

	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return ""
	}

	return currentTime.Add(-time.Duration(info.Uptime) * time.Second).Truncate(time.Second).UTC().String()
}
