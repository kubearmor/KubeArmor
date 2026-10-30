// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package grpcc

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// offsetsCache memoises OffsetsForLib per canonical library path. The ELF
// .rodata scan behind OffsetsForLib is expensive, and the same libgrpc.so is
// typically shared by many processes.
var (
	offsetsCacheMu sync.Mutex
	offsetsCache   = map[string]offsetsResult{}
)

type offsetsResult struct {
	offsets GRPCCOffsets
	err     error
}

func cachedOffsetsForLib(libPath string) (GRPCCOffsets, error) {
	offsetsCacheMu.Lock()
	if r, ok := offsetsCache[libPath]; ok {
		offsetsCacheMu.Unlock()
		return r.offsets, r.err
	}
	offsetsCacheMu.Unlock()

	offsets, err := OffsetsForLib(libPath)

	offsetsCacheMu.Lock()
	offsetsCache[libPath] = offsetsResult{offsets: offsets, err: err}
	offsetsCacheMu.Unlock()
	return offsets, err
}

// ScanPID inspects /proc/<pid>/maps of a single process for libgrpc.so and
// returns a GRPCCTarget per distinct library. Unlike ScanProc it does NOT walk
// every process on the host, so it is safe to call once per newly discovered
// PID from the unified proc walker.
func ScanPID(pid int) ([]GRPCCTarget, error) {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid)) // #nosec G304 -- integer PID
	if err != nil {
		return nil, err // process may have exited
	}
	// Cheap pre-check avoids splitting the whole maps file for the
	// overwhelming majority of processes that do not use libgrpc.
	if !strings.Contains(string(data), "libgrpc.so") {
		return nil, nil
	}

	var targets []GRPCCTarget
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.Contains(line, "libgrpc.so") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 6 || seen[fields[5]] {
			continue
		}
		seen[fields[5]] = true
		libPath, err := filepath.EvalSymlinks(fields[5])
		if err != nil {
			libPath = fields[5]
		}
		offsets, err := cachedOffsetsForLib(libPath)
		if err != nil {
			continue // unsupported version — caller treats as not-a-target
		}
		targets = append(targets, GRPCCTarget{PID: pid, LibPath: libPath, Offsets: offsets})
	}
	return targets, nil
}

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
		data, err := os.ReadFile(mapsPath) // #nosec G304 -- path is /proc/<integer PID>/maps
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
