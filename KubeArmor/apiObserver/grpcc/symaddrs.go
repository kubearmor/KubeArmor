// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// Package grpcc implements ELF-based gRPC-C struct offset discovery and
// /proc scanning for uprobe attachment. Mirrors ssl/symaddrs.go for
// libgrpc.so instead of libssl.so.
package grpcc

import (
	"debug/elf"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// GRPCCOffsets holds version-specific struct field offsets for gRPC-C uprobes.
// MUST stay in sync with struct grpcc_symaddrs in
// KubeArmor/BPF/apiobserver/common/structs.h.
type GRPCCOffsets struct {
	StreamMethodOffset int32 // offsetof(grpc_chttp2_stream, method) — grpc_slice
	StreamIDOffset     int32 // offsetof(grpc_chttp2_stream, id)     — uint32
	TransportFDOffset  int32 // offsetof(grpc_chttp2_transport, fd)  — int
}

// libGRPCGlobs covers Debian/Ubuntu (x86_64 + aarch64), Alpine, and RHEL/Fedora paths.
var libGRPCGlobs = []string{
	"/usr/lib/x86_64-linux-gnu/libgrpc.so.*",
	"/usr/lib/aarch64-linux-gnu/libgrpc.so.*",
	"/usr/lib64/libgrpc.so.*",
	"/usr/lib/libgrpc.so.*",
	"/usr/local/lib/libgrpc.so.*",
	"/usr/local/lib64/libgrpc.so.*",
}

// sonameToVersion maps libgrpc.so SOVERSION integers to the nearest
// known gRPC-C package version for offset table lookup.
// gRPC-C SOVERSION increments independently from the package version;
// this mapping was derived from gRPC CMakeLists.txt history.
var sonameToVersion = map[int]string{
	24: "1.24",
	28: "1.33",
	32: "1.46",
	40: "1.57",
	43: "1.60",
	47: "1.64",
	50: "1.64", // 1.67.x — use 1.64 offsets (struct unchanged)
	53: "1.64", // 1.71.x — use 1.64 offsets (stream.method offset stable)
}

// soname number regex: libgrpc.so.53.0.0 → 53
var sonameRe = regexp.MustCompile(`libgrpc\.so\.(\d+)`)

// LibGRPCPaths returns deduplicated canonical paths to all libgrpc.so
// shared libraries found on the local system.
func LibGRPCPaths() ([]string, error) {
	seen := make(map[string]bool)
	var paths []string
	for _, glob := range libGRPCGlobs {
		matches, err := filepath.Glob(glob)
		if err != nil {
			continue
		}
		for _, m := range matches {
			real, err := filepath.EvalSymlinks(m)
			if err != nil {
				real = m
			}
			if !seen[real] {
				seen[real] = true
				paths = append(paths, real)
			}
		}
	}
	if len(paths) == 0 {
		return nil, errors.New("libgrpc.so not found on this system")
	}
	return paths, nil
}

// versionOffsets maps a gRPC-C version prefix → struct field offsets.
//
// Offsets researched from Pixie/groundcover field work and gRPC source tree
// (https://github.com/grpc/grpc). These are x86_64 values; ARM64 matches
// for the entries marked (*) but may differ for later versions — add a
// dedicated arm64 table once ARM64 CI is available.
//
// To add a new version:
//  1. Build grpc-c from source with debug symbols.
//  2. Run:  pahole -C grpc_chttp2_stream  libgrpc.so
//     pahole -C grpc_chttp2_transport libgrpc.so
//  3. Record stream.method, stream.id, transport.fd offsets.
var versionOffsets = map[string]GRPCCOffsets{
	"1.24": {StreamMethodOffset: 0x68, StreamIDOffset: 0x08, TransportFDOffset: 0x58}, // (*)
	"1.33": {StreamMethodOffset: 0x70, StreamIDOffset: 0x08, TransportFDOffset: 0x58}, // (*)
	"1.46": {StreamMethodOffset: 0x80, StreamIDOffset: 0x08, TransportFDOffset: 0x60}, // (*)
	"1.57": {StreamMethodOffset: 0x88, StreamIDOffset: 0x08, TransportFDOffset: 0x60},
	"1.60": {StreamMethodOffset: 0x90, StreamIDOffset: 0x08, TransportFDOffset: 0x68},
	"1.64": {StreamMethodOffset: 0x90, StreamIDOffset: 0x08, TransportFDOffset: 0x68},
}

// OffsetsForLib returns struct offsets for the given libgrpc.so binary.
// Strategy:
//  1. ELF .rodata scan for an embedded version string.
//  2. Filename/SONAME prefix match as fallback.
func OffsetsForLib(libPath string) (GRPCCOffsets, error) {
    ver, _ := versionStringFromELF(libPath)
    if ver != "" {
        if offsets, ok := lookupByVersion(ver); ok {
            return offsets, nil
        }
    }
    // Filename string fallback: "libgrpc.so.1.60.3" → matches "1.60" substring
    base := filepath.Base(libPath)
    if offsets, ok := lookupByFilename(base); ok {
        return offsets, nil
    }
    // Soname integer fallback: "libgrpc.so.53.0.0" → soname 53 → "1.64"
    if mapped := versionFromFilename(libPath); mapped != "" {
        if offsets, ok := lookupByVersion(mapped); ok {
            return offsets, nil
        }
    }
    return GRPCCOffsets{}, fmt.Errorf(
        "no known struct offsets for %s (detected version=%q); "+
            "add an entry to grpcc.versionOffsets",
        libPath, ver,
    )
}

// versionStringFromELF scans the .rodata section of the ELF binary for a
// gRPC version string embedded at compile time (e.g. "1.46.3").
func versionStringFromELF(libPath string) (string, error) {
	f, err := elf.Open(libPath)
	if err != nil {
		return "", fmt.Errorf("open elf %s: %w", libPath, err)
	}
	defer f.Close()

	sec := f.Section(".rodata")
	if sec == nil {
		return "", fmt.Errorf("no .rodata in %s", libPath)
	}
	data, err := sec.Data()
	if err != nil {
		return "", fmt.Errorf("read .rodata %s: %w", libPath, err)
	}

	// gRPC-C embeds one of these version-marker strings in .rodata.
	for _, needle := range []string{"grpc_version", "grpc.version", "gRPC version"} {
		idx := strings.Index(string(data), needle)
		if idx < 0 {
			continue
		}
		start := idx + len(needle)
		// Skip separator bytes: null, colon, space.
		for start < len(data) && (data[start] == 0 || data[start] == ':' || data[start] == ' ') {
			start++
		}
		end := start
		for end < len(data) && data[end] != 0 && end-start < 32 {
			end++
		}
		if end > start {
			return string(data[start:end]), nil
		}
	}
	return "", fmt.Errorf("version string not found in .rodata of %s", libPath)
}

// lookupByVersion matches a full or 2-component version prefix.
// "1.46.3" → tries "1.46.3", then "1.46".
func lookupByVersion(ver string) (GRPCCOffsets, bool) {
	if o, ok := versionOffsets[ver]; ok {
		return o, true
	}
	if parts := strings.SplitN(ver, ".", 3); len(parts) >= 2 {
		if o, ok := versionOffsets[parts[0]+"."+parts[1]]; ok {
			return o, true
		}
	}
	return GRPCCOffsets{}, false
}

// lookupByFilename tries to match a version token inside the filename.
func lookupByFilename(base string) (GRPCCOffsets, bool) {
	for prefix, offsets := range versionOffsets {
		if strings.Contains(base, prefix) {
			return offsets, true
		}
	}
	return GRPCCOffsets{}, false
}

// ProcMapsPathFmt is the /proc/PID/maps path format.
// Exported so tests can override it with a tmpdir.
var ProcMapsPathFmt = "/proc/%d/maps"

// FindLibInProcMaps returns the first libgrpc.so path found in the process's
// memory map, or an error if none is found.
func FindLibInProcMaps(pid int) (string, error) {
	path := fmt.Sprintf(ProcMapsPathFmt, pid)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "libgrpc.so") {
			if fields := strings.Fields(line); len(fields) >= 6 {
				return fields[5], nil
			}
		}
	}
	return "", fmt.Errorf("libgrpc.so not in %s", path)
}

// In OffsetsForLib, after the ELF .rodata scan fails (version == ""):
func versionFromFilename(libPath string) string {
	m := sonameRe.FindStringSubmatch(filepath.Base(libPath))
	if m == nil {
		return ""
	}
	sonum, _ := strconv.Atoi(m[1])
	if v, ok := sonameToVersion[sonum]; ok {
		log.Debugf("gRPC-C: resolved soname to version soname: %d, mapped_version: %s, lib: %s", sonum, v, libPath)
		return v
	}
	// Unknown soname — try nearest lower entry
	best := 0
	bestVer := ""
	for s, v := range sonameToVersion {
		if s <= sonum && s > best {
			best, bestVer = s, v
		}
	}
	if bestVer != "" {
		log.Debugf("gRPC-C: unknown soname, using nearest lower entry soname: %d, mapped_version: %s, lib: %s", sonum, bestVer, libPath)
		return bestVer
	}
	return ""
}
