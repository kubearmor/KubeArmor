// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package goprobe

import (
	"debug/buildinfo"
	"log/slog"
	"strings"
)

// DefaultOffsetTable returns an offset table with sensible defaults for
// recent gRPC versions (>= 1.60). These offsets correspond to the Go struct
// fields that BPF probes read:
//
//   - transport.Stream.method → GoOffGRPCStreamMethod
//   - transport.Stream.id     → GoOffGRPCStreamID
//   - status.Status.s         → GoOffGRPCStatusS
//   - codes.Code              → GoOffGRPCStatusCode
//
// These defaults are derived from OTel's offset management approach.
func DefaultOffsetTable() GoOffsetTable {
	ot := GoOffsetTable{}

	// transport.Stream.method — Go string at this offset in the Stream struct.
	// Default for gRPC >= 1.60: method is typically at offset 80 (0x50).
	ot.Offsets[GoOffGRPCStreamMethod] = 80

	// transport.Stream.id — uint32.
	// Default: offset 8 within Stream.
	ot.Offsets[GoOffGRPCStreamID] = 8

	// transport.http2Server.conn / http2Client.conn — net.Conn interface (unused by new probes but kept).
	ot.Offsets[GoOffGRPCTransportConn] = -1

	// status.Status.s (pointer to internal status struct).
	// Default: offset 0 within Status.
	ot.Offsets[GoOffGRPCStatusS] = 0

	// codes.Code within the internal status struct.
	// Default: offset 0 (Code int32 is the first field).
	ot.Offsets[GoOffGRPCStatusCode] = 0

	// FD offsets (not used by goroutine-based probes, but populated for potential future use).
	ot.Offsets[GoOffFDSysfd] = 16  // internal/poll.FD.Sysfd
	ot.Offsets[GoOffConnFD] = 16   // net.conn.fd
	ot.Offsets[GoOffFDLaddr] = 32  // netFD.laddr
	ot.Offsets[GoOffFDRaddr] = 48  // netFD.raddr
	ot.Offsets[GoOffTCPAddrPort] = 16
	ot.Offsets[GoOffTCPAddrIP] = 0

	// Version flags (default: not set).
	ot.Offsets[GoOffGRPCV160] = 0
	ot.Offsets[GoOffGRPCV169] = 0
	ot.Offsets[GoOffGRPCServerStreamStream] = -1
	ot.Offsets[GoOffGRPCServerStreamST] = -1
	ot.Offsets[GoOffGRPCStreamST] = -1

	return ot
}

// ApplyVersionOffsets adjusts the offset table based on the detected gRPC library version.
func ApplyVersionOffsets(ot *GoOffsetTable, version string) {
	if version == "" {
		return
	}

	// Normalize version to semver format.
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	slog.Info("Applying gRPC version-specific offsets", "version", version)

	// gRPC >= 1.60: handleStream has extra context parameter.
	if versionGE(version, "v1.60.0") {
		ot.Offsets[GoOffGRPCV160] = 1
	}

	// gRPC >= 1.69: Server stream wrapper changes.
	if versionGE(version, "v1.69.0") {
		ot.Offsets[GoOffGRPCV169] = 1
	}

	// gRPC >= 1.77: Further Server stream reorganization.
	// (Adjust offsets when support is added.)
}

// versionGE does a simple lexicographic comparison of Go module version strings.
// Both a and b must have a "v" prefix (e.g. "v1.60.0").
// This is sufficient for gRPC versions which follow strict semver.
func versionGE(a, b string) bool {
	a = strings.TrimPrefix(a, "v")
	b = strings.TrimPrefix(b, "v")
	return a >= b
}

// GetGrpcLibVersion attempts to detect the gRPC library version from the
// Go binary's build info. Returns an empty string if not detected.
func GetGrpcLibVersion(binaryPath string) string {
	info, err := buildinfo.ReadFile(binaryPath)
	if err != nil {
		return ""
	}

	for _, dep := range info.Deps {
		if dep.Path == "google.golang.org/grpc" {
			slog.Info("Detected gRPC version", "version", dep.Version, "binary", binaryPath)
			return dep.Version
		}
	}
	return ""
}

// DefaultCommonSymaddrs returns default common symaddrs for backward compatibility.
func DefaultCommonSymaddrs() GoCommonSymaddrs {
	return GoCommonSymaddrs{
		InternalSyscallConn:   -1,
		TlsConn:               -1,
		NetTCPConn:             -1,
		FD_SysfdOffset:         16,
		TlsConnConnOffset:      0,
		SyscallConnConnOffset:  8,
		G_goidOffset:           152,
		G_addrOffset:           -8,
	}
}
