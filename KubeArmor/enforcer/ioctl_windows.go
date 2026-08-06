//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package enforcer

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ============================================================
// IOCTL constants — must match driver's DeviceIOCTL.h exactly
// ============================================================

const (
	// CTL_CODE(DEVICE_KARMOR=0x8022, Function, METHOD_BUFFERED=0, FILE_WRITE_DATA=0x2)
	// Formula: (DeviceType << 16) | (Access << 14) | (Function << 2) | Method
	ioctlAddRule    = (0x8022 << 16) | (0x2 << 14) | (0x800 << 2) | 0 // 0x8022A000
	ioctlRemoveRule = (0x8022 << 16) | (0x2 << 14) | (0x801 << 2) | 0 // 0x8022A004
	ioctlClearRules = (0x8022 << 16) | (0x2 << 14) | (0x802 << 2) | 0 // 0x8022A008

	// Rule types (matches RULE_TYPE enum)
	ruleTypeFile    uint16 = 1
	ruleTypeProcess uint16 = 2

	// Match types (matches MATCH_TYPE enum)
	matchPath      uint16 = 1
	matchDirectory uint16 = 2
	matchPattern   uint16 = 3

	// Rule actions (matches RULE_ACTION_IOCTL enum)
	ruleActionAudit int16 = 0
	ruleActionBlock int16 = 1
	ruleActionAllow int16 = 2

	// Rule flags (matches RULE_FLAG_* defines)
	ruleFlagReadOnly  uint16 = 0x0001
	ruleFlagRecursive uint16 = 0x0002
	ruleFlagOwnerOnly uint16 = 0x0004

	// Max path length (matches MAX_PATH_LENGTH in DeviceIOCTL.h)
	maxPathLength = 520

	// Driver device path
	karmorDevicePath = `\\.\Karmor`
)

// userRuleRequest matches the C struct USER_RULE_REQUEST in DeviceIOCTL.h.
// Layout: RuleType(2) + MatchType(2) + Action(2) + Flags(2) + Path(520*2=1040) = 1048 bytes
type userRuleRequest struct {
	RuleType  uint16
	MatchType uint16
	Action    int16
	Flags     uint16
	Path      [maxPathLength]uint16
}

// openDriverDevice opens a handle to the Karmor driver device for IOCTL communication.
func openDriverDevice() (windows.Handle, error) {
	pathPtr, err := windows.UTF16PtrFromString(karmorDevicePath)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("UTF16PtrFromString: %w", err)
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,   // no sharing
		nil, // default security
		windows.OPEN_EXISTING,
		0, // no flags
		0, // no template
	)
	if err != nil {
		return windows.InvalidHandle, fmt.Errorf("CreateFile(%s): %w", karmorDevicePath, err)
	}

	return handle, nil
}

// sendIoctl sends an IOCTL to the driver with an optional userRuleRequest payload.
// If req is nil (e.g. for IOCTL_CLEAR_RULES), no input buffer is sent.
func sendIoctl(handle windows.Handle, ioctlCode uint32, req *userRuleRequest) error {
	var inBuf *byte
	var inSize uint32

	if req != nil {
		inBuf = (*byte)(unsafe.Pointer(req))
		inSize = uint32(unsafe.Sizeof(*req))
	}

	var bytesReturned uint32
	err := windows.DeviceIoControl(
		handle,
		ioctlCode,
		inBuf,
		inSize,
		nil, // no output buffer
		0,
		&bytesReturned,
		nil, // synchronous
	)
	if err != nil {
		return fmt.Errorf("DeviceIoControl(0x%X): %w", ioctlCode, err)
	}

	return nil
}

// buildRuleRequest creates a userRuleRequest struct with the given parameters.
// The ntPath is converted to UTF-16 and copied into the fixed-size Path array.
func buildRuleRequest(ruleType, matchType uint16, action int16, flags uint16, ntPath string) (*userRuleRequest, error) {
	pathUTF16, err := windows.UTF16FromString(ntPath)
	if err != nil {
		return nil, fmt.Errorf("UTF16FromString: %w", err)
	}

	if len(pathUTF16) > maxPathLength {
		return nil, fmt.Errorf("path too long (%d chars, max %d): %s", len(pathUTF16), maxPathLength, ntPath)
	}

	req := &userRuleRequest{
		RuleType:  ruleType,
		MatchType: matchType,
		Action:    action,
		Flags:     flags,
	}

	copy(req.Path[:], pathUTF16)

	return req, nil
}

// mapActionString converts a KubeArmor policy action string to the driver's int16 action value.
func mapActionString(action string) int16 {
	switch action {
	case "Block":
		return ruleActionBlock
	case "Allow":
		return ruleActionAllow
	case "Audit":
		return ruleActionAudit
	default:
		// Default to audit for unknown actions
		return ruleActionAudit
	}
}
