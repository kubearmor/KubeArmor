//go:build windows
// +build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// pathconv_windows.go — Converts Win32 (DOS) file paths to NT kernel namespace
// paths for use in minifilter rule matching.
//
// Adapted from d:\poc\dos2nt.go
//
// Two strategies are used depending on whether the target path exists:
//   1. GetFinalPathNameByHandleW (VOLUME_NAME_NT) — fully resolves mount points
//      and reparse points. Matches FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED).
//   2. QueryDosDeviceW fallback — resolves only the drive letter to a device name.
//      Used when the file does not yet exist.

package enforcer

import (
	"fmt"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	modKernel32                  = windows.NewLazySystemDLL("kernel32.dll")
	procGetFinalPathNameByHandle = modKernel32.NewProc("GetFinalPathNameByHandleW")
	procQueryDosDevice           = modKernel32.NewProc("QueryDosDeviceW")
)

const (
	fileNameNormalized = 0x0
	volumeNameNT       = 0x2
)

// ntPathFromHandle opens a handle to dosPath and calls GetFinalPathNameByHandleW
// with VOLUME_NAME_NT to get the fully resolved NT device path.
// This matches FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED) exactly.
func ntPathFromHandle(dosPath string) (string, error) {
	pathPtr, err := syscall.UTF16PtrFromString(dosPath)
	if err != nil {
		return "", fmt.Errorf("UTF-16 conversion: %w", err)
	}

	// FILE_FLAG_BACKUP_SEMANTICS is required to open a directory handle.
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ,
		windows.FILE_SHARE_READ,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS,
		0,
	)
	if err != nil {
		return "", fmt.Errorf("CreateFile: %w", err)
	}
	defer windows.CloseHandle(handle)

	buf := make([]uint16, 512)
	r0, _, _ := procGetFinalPathNameByHandle.Call(
		uintptr(handle),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(volumeNameNT|fileNameNormalized),
	)
	if r0 == 0 {
		return "", fmt.Errorf("GetFinalPathNameByHandleW returned 0")
	}
	// If buffer was too small, r0 is the required size — retry.
	if r0 >= uintptr(len(buf)) {
		buf = make([]uint16, r0+1)
		r0, _, _ = procGetFinalPathNameByHandle.Call(
			uintptr(handle),
			uintptr(unsafe.Pointer(&buf[0])),
			uintptr(len(buf)),
			uintptr(volumeNameNT|fileNameNormalized),
		)
		if r0 == 0 {
			return "", fmt.Errorf("GetFinalPathNameByHandleW (retry) returned 0")
		}
	}

	return syscall.UTF16ToString(buf[:r0]), nil
}

// queryDosDevice calls QueryDosDeviceW for a drive name like "C:" and
// returns the NT device path it maps to (e.g. "\Device\HarddiskVolume3").
func queryDosDevice(driveLetter string) (string, error) {
	drivePtr, err := syscall.UTF16PtrFromString(driveLetter)
	if err != nil {
		return "", fmt.Errorf("UTF-16 conversion: %w", err)
	}

	buf := make([]uint16, 256)
	r0, _, callErr := procQueryDosDevice.Call(
		uintptr(unsafe.Pointer(drivePtr)),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r0 == 0 {
		return "", fmt.Errorf("QueryDosDeviceW: %w", callErr)
	}

	// The buffer is a multi-string (null-separated).
	// The first entry is the device name we want.
	device := syscall.UTF16ToString(buf[:r0])
	if idx := strings.IndexByte(device, 0); idx >= 0 {
		device = device[:idx]
	}
	device = strings.TrimRight(device, "\x00")
	return device, nil
}

// ntPathFromDriveMapping resolves the drive letter of dosPath to an NT device
// via QueryDosDeviceW and appends the rest of the path. This does NOT resolve
// junctions or reparse points inside the path; it is a best-effort fallback
// for non-existent targets.
func ntPathFromDriveMapping(dosPath string) (string, error) {
	// Validate: must be an absolute path of the form X:\...
	if len(dosPath) < 3 || dosPath[1] != ':' || (dosPath[2] != '\\' && dosPath[2] != '/') {
		return "", fmt.Errorf("path must be absolute (e.g. C:\\foo\\bar): %q", dosPath)
	}

	driveLetter := strings.ToUpper(string(dosPath[0])) + ":"
	device, err := queryDosDevice(driveLetter)
	if err != nil {
		return "", err
	}

	// Replace the drive-letter prefix with the NT device name.
	// dosPath[2:] is everything from the first backslash, e.g. "\foo\bar.txt"
	rest := strings.ReplaceAll(dosPath[2:], "/", "\\")
	return device + rest, nil
}

// convertToNTPath converts a Win32 DOS path to an NT namespace path suitable
// for comparison against FltGetFileNameInformation(FLT_FILE_NAME_NORMALIZED)
// in the Karmor minifilter driver.
//
// Strategy selection:
//   - File/directory exists  → GetFinalPathNameByHandleW (fully resolved)
//   - Does not exist         → QueryDosDeviceW drive mapping + concatenation
func convertToNTPath(dosPath string) (string, error) {
	if path, err := ntPathFromHandle(dosPath); err == nil {
		return path, nil
	}

	if path, err := ntPathFromDriveMapping(dosPath); err == nil {
		return path, nil
	}

	return "", fmt.Errorf("failed to convert path to NT format: %s", dosPath)
}
