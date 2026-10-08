// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build darwin

package common

import (
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// GetOSImage returns a human-readable OS name and version, e.g. "macOS 26.6.2",
// from `sw_vers`, falling back to `uname -s`/`uname -r`.
func GetOSImage() string {
	name := strings.TrimSpace(GetCommandOutputWithoutErr("sw_vers", []string{"-productName"}))
	if name == "" {
		sys := strings.TrimSpace(GetCommandOutputWithoutErr("uname", []string{"-s"}))
		rel := strings.TrimSpace(GetCommandOutputWithoutErr("uname", []string{"-r"}))
		return strings.TrimSpace(sys + " " + rel)
	}
	ver := strings.TrimSpace(GetCommandOutputWithoutErr("sw_vers", []string{"-productVersion"}))
	return strings.TrimSpace(name + " " + ver)
}

// GetMachineID returns a stable machine identifier. It checks extraPaths first,
// then the IOPlatformUUID reported by `ioreg`.
func GetMachineID(extraPaths ...string) string {
	if id := readFirstNonEmptyFile(extraPaths...); id != "" {
		return id
	}
	out := GetCommandOutputWithoutErr("ioreg", []string{"-rd1", "-c", "IOPlatformExpertDevice"})
	for line := range strings.SplitSeq(out, "\n") {
		if !strings.Contains(line, "IOPlatformUUID") {
			continue
		}
		// line looks like:  "IOPlatformUUID" = "3FB16E87-82D9-5EA5-A9EF-D96E884B3CB9"
		if f := strings.Split(line, `"`); len(f) >= 4 {
			return f[3]
		}
	}
	return ""
}

// GetSupportedLSMs returns "" — Linux Security Modules do not exist on macOS, so
// KubeArmor has no host enforcer here and runs in audit-only mode.
func GetSupportedLSMs() string { return "" }

// GetBootTime returns the system boot time as a string.
func GetBootTime() string {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil || tv == nil {
		return ""
	}
	sec, nsec := tv.Unix()
	return time.Unix(sec, nsec).Truncate(time.Second).UTC().String()
}

// GetUptimeTimestamp returns the boot time as fractional unix seconds, from the
// kern.boottime sysctl.
func GetUptimeTimestamp() float64 {
	tv, err := unix.SysctlTimeval("kern.boottime")
	if err != nil || tv == nil {
		return float64(time.Now().UnixNano()/1000) / 1000000.0
	}
	sec, nsec := tv.Unix()
	return float64(sec) + float64(nsec)/1e9
}
