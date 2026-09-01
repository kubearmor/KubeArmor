// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

package common

import (
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// GetOSImage returns a human-readable OS name and version, e.g.
// "Ubuntu 22.04.3 LTS". It reads PRETTY_NAME from /etc/os-release (present on
// every modern Linux, systemd or not) and falls back to `hostnamectl`.
func GetOSImage() string {
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for line := range strings.SplitSeq(string(data), "\n") {
			if v, ok := strings.CutPrefix(strings.TrimSpace(line), "PRETTY_NAME="); ok {
				if v = strings.Trim(v, `"`); v != "" {
					return v
				}
			}
		}
	}
	for line := range strings.SplitSeq(GetCommandOutputWithoutErr("hostnamectl", []string{}), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Operating System:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// GetMachineID returns a stable machine identifier. It checks extraPaths first,
// then the standard /etc/machine-id and /var/lib/dbus/machine-id, then the
// `hostnamectl` "Machine ID:" line.
func GetMachineID(extraPaths ...string) string {
	paths := append(append([]string{}, extraPaths...), "/etc/machine-id", "/var/lib/dbus/machine-id")
	if id := readFirstNonEmptyFile(paths...); id != "" {
		return id
	}
	for line := range strings.SplitSeq(GetCommandOutputWithoutErr("hostnamectl", []string{}), "\n") {
		if v, ok := strings.CutPrefix(strings.TrimSpace(line), "Machine ID:"); ok {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

// GetSupportedLSMs returns the kernel's active Linux Security Module list
// (e.g. "lockdown,capability,yama,apparmor,bpf") from /sys/kernel/security/lsm,
// or "" if securityfs is not mounted or the file is absent/empty. It never logs.
func GetSupportedLSMs() string {
	return readFirstNonEmptyFile("/sys/kernel/security/lsm")
}

// GetBootTime returns the system boot time as a string.
// credits: https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/util/boottime_util_linux.go
func GetBootTime() string {
	currentTime := time.Now()

	var info unix.Sysinfo_t
	if err := unix.Sysinfo(&info); err != nil {
		return ""
	}

	return currentTime.Add(-time.Duration(info.Uptime) * time.Second).Truncate(time.Second).UTC().String()
}

// GetUptimeTimestamp returns the boot time as fractional unix seconds, derived
// from the seconds-since-boot in the first field of /proc/uptime.
func GetUptimeTimestamp() float64 {
	now := time.Now().UTC()

	res := GetCommandOutputWithoutErr("cat", []string{"/proc/uptime"})
	uptimeDiff := strings.Split(res, " ")[0]
	parts := strings.Split(uptimeDiff, ".")
	if len(parts) < 2 || parts[0] == "" {
		// /proc/uptime unreadable/malformed: no boot-time offset available
		return float64(now.UnixNano()/1000) / 1000000.0
	}

	uptimeDiffSec, _ := strconv.ParseInt(parts[0], 10, 64) // second
	uptimeDiffMil, _ := strconv.ParseInt(parts[1], 10, 64) // milli second

	uptime := now.Add(-time.Second * time.Duration(uptimeDiffSec))
	uptime = uptime.Add(-time.Millisecond * time.Duration(uptimeDiffMil))

	return float64(uptime.UnixNano()/1000) / 1000000.0
}
