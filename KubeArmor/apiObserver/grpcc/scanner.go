// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package grpcc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// GRPCCTarget is a process that has libgrpc.so loaded with known struct offsets.
type GRPCCTarget struct {
	PID     int
	LibPath string
	Offsets GRPCCOffsets
}

// ScanProc walks /proc/*/maps for processes using libgrpc.so and returns
// GRPCCTarget entries for each (pid, libPath) pair whose gRPC-C version is
// in the versionOffsets table. Processes with unsupported versions are logged
// by the caller but not returned.
//
// ELF scanning is deduplicated: each unique library path is scanned only once
// regardless of how many processes share it (e.g. multiple Python workers).
func ScanProc() ([]GRPCCTarget, error) {
	dirs, err := os.ReadDir("/proc")
	if err != nil {
		return nil, fmt.Errorf("scan /proc: %w", err)
	}

	type libResult struct {
		offsets GRPCCOffsets
		err     error
	}
	// Cache ELF scan results keyed by canonical library path.
	libCache := make(map[string]libResult)

	var targets []GRPCCTarget
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		pid, err := strconv.Atoi(d.Name())
		if err != nil {
			continue // not a PID directory
		}

		mapsPath := fmt.Sprintf("/proc/%d/maps", pid)
		data, err := os.ReadFile(mapsPath)
		if err != nil {
			continue // process may have exited between ReadDir and ReadFile
		}

		// Deduplicate multiple mappings of the same library within one process
		// (e.g. different virtual address ranges for the same .so).
		seenInProc := make(map[string]bool)
		for _, line := range strings.Split(string(data), "\n") {
			if !strings.Contains(line, "libgrpc.so") {
				continue
			}
			fields := strings.Fields(line)
			if len(fields) < 6 {
				continue
			}
			rawPath := fields[5]
			if seenInProc[rawPath] {
				continue
			}
			seenInProc[rawPath] = true

			// Resolve symlinks so the cache key is stable across versions.
			libPath, err := filepath.EvalSymlinks(rawPath)
			if err != nil {
				libPath = rawPath
			}

			res, cached := libCache[libPath]
			if !cached {
				offsets, err := OffsetsForLib(libPath)
				res = libResult{offsets: offsets, err: err}
				libCache[libPath] = res
			}
			if res.err != nil {
				// Caller logs unsupported versions — we just skip.
				continue
			}
			targets = append(targets, GRPCCTarget{
				PID:     pid,
				LibPath: libPath,
				Offsets: res.offsets,
			})
		}
	}
	return targets, nil
}
