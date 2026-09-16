// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build windows

package common

// NOTE: KubeArmor does not yet build for GOOS=windows, so this file is not part of
// the compile/CI path. It exists to establish the platform slot and a best-effort
// implementation for when Windows support is added.

import (
	"strings"
	"time"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// GetOSImage returns e.g. "Windows 10 Pro 22H2" from the registry.
func GetOSImage() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Windows NT\CurrentVersion`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()

	name, _, _ := k.GetStringValue("ProductName")
	ver, _, _ := k.GetStringValue("DisplayVersion")
	return strings.TrimSpace(name + " " + ver)
}

// GetMachineID returns the Windows MachineGuid, after checking any caller paths.
func GetMachineID(extraPaths ...string) string {
	if id := readFirstNonEmptyFile(extraPaths...); id != "" {
		return id
	}
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()

	id, _, _ := k.GetStringValue("MachineGuid")
	return strings.TrimSpace(id)
}

// GetSupportedLSMs returns "" — Linux Security Modules do not exist on Windows.
func GetSupportedLSMs() string { return "" }

// GetBootTime derives boot time from the system uptime (GetTickCount64).
func GetBootTime() string {
	uptime := time.Duration(windows.GetTickCount64()) * time.Millisecond
	return time.Now().Add(-uptime).Truncate(time.Second).UTC().String()
}

// GetUptimeTimestamp returns the boot time as fractional unix seconds, derived
// from the system uptime (GetTickCount64).
func GetUptimeTimestamp() float64 {
	uptime := time.Duration(windows.GetTickCount64()) * time.Millisecond
	boot := time.Now().Add(-uptime)
	return float64(boot.UnixNano()/1000) / 1000000.0
}
