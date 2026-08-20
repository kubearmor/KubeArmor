//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package enforcer is responsible for setting up and handling policy updates for supported enforcers including AppArmor, SELinux and BPFLSM
package enforcer

import (
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	"golang.org/x/sys/windows"
)

var (
	_ RuntimeEnforcer = (*RuntimeEnforcerWin)(nil)
)

// RuntimeEnforcerWin Structure
type RuntimeEnforcerWin struct {
	// logger
	Logger *fd.Feeder

	// LSM type
	EnforcerType string

	// Driver device handle for IOCTL communication
	deviceHandle windows.Handle

	// Mutex for serializing policy updates
	mu sync.Mutex

	// AppLocker event-log poller — emits MatchedHostPolicy alerts for
	// processes blocked by AppLocker rules.
	appLockerPoller *AppLockerPoller
}

// NewRuntimeEnforcer Function
func NewRuntimeEnforcer(node tp.Node, logger *fd.Feeder, monitor *mon.SystemMonitor) RuntimeEnforcer {
	re := &RuntimeEnforcerWin{}
	re.Logger = logger
	re.EnforcerType = "Minifilter"
	re.deviceHandle = windows.InvalidHandle

	// Attempt to start the Karmor driver if it's not already running.
	// We ignore the error here because if it's already running or if we lack
	// permissions, the subsequent openDriverDevice() call will catch the real issue.
	_ = exec.Command("fltmc.exe", "load", "kubearmor").Run()

	// Attempt to open the Karmor driver device for IOCTL communication.
	// If the driver is not loaded, enforcement is disabled but monitoring
	// (via FltMgr communication port) still works.
	handle, err := openDriverDevice()
	if err != nil {
		logger.Errf("Failed to open Karmor driver device: %v (file enforcement disabled)", err)
	} else {
		re.deviceHandle = handle
		logger.Printf("Karmor driver device opened successfully for enforcement")
	}

	// Start the AppLocker event-log poller. It polls every 5 seconds for new
	// AppLocker block events (Event IDs 8003/8004/8006) and emits them as
	// MatchedHostPolicy alerts through the feeder pipeline.
	// If AppLocker is not present the poller emits nothing (no-op).
	re.appLockerPoller = NewAppLockerPoller(logger)
	re.appLockerPoller.Start()
	logger.Printf("AppLocker event-log poller started")

	logger.UpdateEnforcer(re.EnforcerType)
	return re
}

func (re *RuntimeEnforcerWin) GetEnforcerType() string {
	return re.EnforcerType
}

// RegisterContainer registers container identifiers to BPFEnforcer Map
func (re *RuntimeEnforcerWin) RegisterContainer(containerID string, pidns, mntns uint32) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UnregisterContainer removes container identifiers from BPFEnforcer Map
func (re *RuntimeEnforcerWin) UnregisterContainer(containerID string) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateAppArmorProfiles Function
func (re *RuntimeEnforcerWin) UpdateAppArmorProfiles(podName string, action string, profiles map[string]string, privilegedProfiles map[string]struct{}) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateSecurityPolicies Function
func (re *RuntimeEnforcerWin) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}
}

// UpdateHostSecurityPolicies translates KubeArmor host security policies
// into driver-level rules and sends them to the Karmor minifilter via IOCTL.
//
// This uses a clear-and-reload strategy: all existing rules in the driver are
// cleared first, then the full policy set is re-sent. This is simple and
// correct, with a brief enforcement gap during the reload.
func (re *RuntimeEnforcerWin) UpdateHostSecurityPolicies(secPolicies []tp.HostSecurityPolicy) {
	// skip if runtime enforcer is not active
	if re == nil {
		return
	}

	// skip if driver device is not open
	if re.deviceHandle == windows.InvalidHandle {
		return
	}
	re.Logger.Printf("Device Handle: %+v \n", re.deviceHandle)

	re.mu.Lock()
	defer re.mu.Unlock()

	// Step 1: Clear all existing rules in the driver
	if err := sendIoctl(re.deviceHandle, ioctlClearRules, nil); err != nil {
		re.Logger.Errf("Failed to clear rules in driver: %v", err)
		return
	}

	// Clear the Go-side policy name registry in sync with the driver clear
	mon.GetPolicyNameRegistry().Clear()

	// Apply AppLocker policies for process enforcement
	errAppLocker := applyAppLockerPolicy(secPolicies)
	if errAppLocker == nil {
		re.Logger.Printf("AppLocker policy applied successfully for process enforcement")
	} else {
		re.Logger.Printf("AppLocker policy failed or unavailable, falling back to driver process enforcement: %v", errAppLocker)
	}

	fileRuleCount := 0
	dirRuleCount := 0
	processRuleCount := 0

	// Step 2: Send new rules from each policy
	for _, policy := range secPolicies {
		defaultAction := mapActionString(policy.Spec.Action)

		// === File matchPaths ===
		for _, fp := range policy.Spec.File.MatchPaths {
			action := resolveAction(fp.Action, defaultAction)
			flags := uint16(0)
			if fp.ReadOnly {
				flags |= ruleFlagReadOnly
			}

			ntPath, err := convertToNTPath(fp.Path)
			if err != nil {
				re.Logger.Errf("Path conversion failed for %s: %v", fp.Path, err)
				continue
			}

			req, err := buildRuleRequest(ruleTypeFile, matchPath, action, flags, ntPath)
			if err != nil {
				re.Logger.Errf("Failed to build rule request for %s: %v", fp.Path, err)
				continue
			}

			if err := sendIoctl(re.deviceHandle, ioctlAddRule, req); err != nil {
				re.Logger.Errf("Failed to send file rule for %s: %v", fp.Path, err)
				continue
			}

			mon.GetPolicyNameRegistry().Register(ntPath, "path", policy.Metadata["name"])
			fileRuleCount++
		}

		// === File matchDirectories ===
		for _, dp := range policy.Spec.File.MatchDirectories {
			action := resolveAction(dp.Action, defaultAction)
			flags := uint16(0)
			if dp.ReadOnly {
				flags |= ruleFlagReadOnly
			}
			if dp.Recursive {
				flags |= ruleFlagRecursive
			}

			ntPath, err := convertToNTPath(dp.Directory)
			if err != nil {
				re.Logger.Warnf("Path conversion failed for directory %s: %v (skipping)", dp.Directory, err)
				continue
			}

			// Ensure directory path ends with backslash for prefix matching
			if !strings.HasSuffix(ntPath, "\\") {
				ntPath += "\\"
			}

			req, err := buildRuleRequest(ruleTypeFile, matchDirectory, action, flags, ntPath)
			if err != nil {
				re.Logger.Errf("Failed to build directory rule request for %s: %v", dp.Directory, err)
				continue
			}

			if err := sendIoctl(re.deviceHandle, ioctlAddRule, req); err != nil {
				re.Logger.Errf("Failed to send directory rule for %s: %v", dp.Directory, err)
				continue
			}

			mon.GetPolicyNameRegistry().Register(ntPath, "directory", policy.Metadata["name"])
			dirRuleCount++
		}

		// === File matchPatterns ===
		for _, pp := range policy.Spec.File.MatchPatterns {
			action := resolveAction(pp.Action, defaultAction)
			flags := uint16(0)
			if pp.ReadOnly {
				flags |= ruleFlagReadOnly
			}

			// Normalize forward slashes to backslashes.
			pattern := strings.ReplaceAll(pp.Pattern, "/", "\\")

			// The minifilter always sees full NT device paths, e.g.:
			//   \Device\HarddiskVolume3\Windows\Temp\debug.log
			//
			// A relative pattern like \Windows\Temp\*.log will NEVER match
			// because it doesn't cover the \Device\HarddiskVolumeN prefix.
			//
			// Fix: if the pattern does not already start with \Device\ (an
			// absolute NT path) or with ** (an explicit any-depth wildcard),
			// prepend **\ so the pattern becomes **\Windows\Temp\*.log.
			// The driver's GlobMatch treats ** as "match any chars including
			// path separators", so it will find the suffix anywhere in the
			// full NT path.
			if !strings.HasPrefix(pattern, "\\Device\\") && !strings.HasPrefix(pattern, "**") {
				pattern = "**" + pattern
			}

			req, err := buildRuleRequest(ruleTypeFile, matchPattern, action, flags, pattern)
			if err != nil {
				re.Logger.Errf("Failed to build pattern rule request for %s: %v", pp.Pattern, err)
				continue
			}

			if err := sendIoctl(re.deviceHandle, ioctlAddRule, req); err != nil {
				re.Logger.Errf("Failed to send pattern rule for %s: %v", pp.Pattern, err)
				continue
			}

			mon.GetPolicyNameRegistry().Register(pattern, "pattern", policy.Metadata["name"])
			re.Logger.Printf("Pattern rule sent: %s -> %s (action=%d, flags=0x%04X)", pp.Pattern, pattern, action, flags)
			fileRuleCount++
		}

		// === Process matchPaths ===
		for _, pp := range policy.Spec.Process.MatchPaths {
			action := resolveAction(pp.Action, defaultAction)
			pathStr := string(pp.Path)
			lowerPath := strings.ToLower(pathStr)
			ext := filepath.Ext(lowerPath)

			var rType uint16
			var mType uint16 = matchPath
			var targetName string

			switch ext {
			case ".dll", ".ocx", ".ps1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh":
				// DLLs and Scripts cannot be blocked by driver Process rules (PsSetCreateProcessNotifyRoutineEx)
				// because they are interpreted/loaded by a host process (powershell.exe, etc.).
				// To provide driver fallback if AppLocker is disabled, we translate these into
				// File rules, which block the host process from reading or executing the file.
				rType = ruleTypeFile

				// Driver File rules expect NT paths.
				ntPath, err := convertToNTPath(pathStr)
				if err != nil {
					re.Logger.Warnf("Path conversion failed for script/dll fallback %s: %v", pathStr, err)
					continue
				}
				targetName = ntPath
			default:
				// Traditional EXEs (or Appx) are handled by driver Process rules.
				rType = ruleTypeProcess

				// For process rules the driver uses suffix matching, so we store
				// just the base filename (e.g. "Notepad.exe").
				targetName = extractProcessRuleName(pathStr)
				if targetName == "" {
					re.Logger.Errf("Empty process rule name for path %s, skipping", pathStr)
					continue
				}
			}

			req, err := buildRuleRequest(rType, mType, action, 0, targetName)
			if err != nil {
				re.Logger.Errf("Failed to build rule request for %s: %v", pathStr, err)
				continue
			}

			if err := sendIoctl(re.deviceHandle, ioctlAddRule, req); err != nil {
				re.Logger.Errf("Failed to send process rule for %s: %v", pathStr, err)
				continue
			}

			if rType == ruleTypeFile {
				mon.GetPolicyNameRegistry().Register(targetName, "path", policy.Metadata["name"])
				re.Logger.Printf("Process rule (Script/DLL fallback) sent as File rule: %s -> %s (action=%d)", pathStr, targetName, action)
				fileRuleCount++
			} else {
				re.Logger.Printf("Process rule sent: %s -> %s (action=%d)", pathStr, targetName, action)
				processRuleCount++
			}
		}
	}

	re.Logger.Printf("Policy update complete: %d file rules, %d directory rules, %d process rules sent to driver",
		fileRuleCount, dirRuleCount, processRuleCount)
}

// resolveAction determines the effective action for a rule.
// If the rule has its own action, use it; otherwise fall back to the policy default.
func resolveAction(ruleAction string, defaultAction int16) int16 {
	if ruleAction != "" {
		return mapActionString(ruleAction)
	}
	return defaultAction
}

// extractProcessRuleName extracts the matching key to store in the driver for
// a process rule. The driver uses suffix matching, so we store just the
// filename (e.g. "Notepad.exe") when no directory separator is present,
// or the full Win32 path normalized with backslashes when a full path is given.
// This way "Notepad.exe" matches any install location (System32, WindowsApps…).
func extractProcessRuleName(policyPath string) string {
	// Normalize slashes
	p := strings.ReplaceAll(policyPath, "/", "\\")
	// If no backslash in the path, treat it as a bare filename
	if !strings.Contains(p, "\\") {
		return p
	}
	// If it's a full path, use just the base name so suffix matching works
	// regardless of the install directory (handles UWP / WindowsApps).
	return filepath.Base(p)
}

// DestroyRuntimeEnforcer Function
func (re *RuntimeEnforcerWin) DestroyRuntimeEnforcer() error {
	// skip if runtime enforcer is not active
	if re == nil {
		return nil
	}

	// Stop the AppLocker poller first
	if re.appLockerPoller != nil {
		re.appLockerPoller.Stop()
		re.Logger.Printf("AppLocker event-log poller stopped")
	}

	// Remove any AppLocker policies that KubeArmor applied so enforcement
	// does not persist after KubeArmor exits.
	if err := clearAppLockerPolicy(); err != nil {
		re.Logger.Warnf("Failed to clear AppLocker policy on shutdown: %v", err)
	} else {
		re.Logger.Printf("AppLocker policy cleared (NotConfigured)")
	}

	if re.deviceHandle != 0 && re.deviceHandle != windows.InvalidHandle {
		// Clear all rules before disconnecting so enforcement stops cleanly
		if err := sendIoctl(re.deviceHandle, ioctlClearRules, nil); err != nil {
			re.Logger.Errf("Failed to clear rules during shutdown: %v", err)
		}
		windows.CloseHandle(re.deviceHandle)
		re.deviceHandle = windows.InvalidHandle
		re.Logger.Printf("Karmor driver device closed, enforcement stopped")
	}

	return nil
}
