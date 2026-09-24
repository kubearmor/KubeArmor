// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"fmt"
	"os"
	"sync"
	"syscall"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"

	"github.com/kubearmor/KubeArmor/KubeArmor/apiObserver/ssl"
)

// ProcSnapshot is everything collected per-PID in a single /proc walk.
// This struct is cheap to copy and contains no pointers to mutable state.
type ProcSnapshot struct {
	PID      uint32 // process ID
	ExePath  string // from readlink /proc/<pid>/exe
	HostPath string // resolved through /proc/<pid>/root (for containerised binaries)
	Inode    uint64 // exe inode — THE change-detection key
}

// ProcCache tracks known PIDs and their binary inodes. It deduplicates
// the three independent /proc walkers (SSL, Go HTTP/2, gRPC-C) into a
// single inode-indexed cache. Steady-state ticks become no-ops because
// all known inodes are skipped.
type ProcCache struct {
	mu      sync.RWMutex
	byPID   map[uint32]ProcSnapshot // pid → last seen snapshot
	byInode map[uint64]uint32       // inode → first PID (deduplicate same binary)
}

// NewProcCache creates an empty cache.
func NewProcCache() *ProcCache {
	return &ProcCache{
		byPID:   make(map[uint32]ProcSnapshot),
		byInode: make(map[uint64]uint32),
	}
}

// Diff walks /proc once, compares against the cache, and returns only
// genuinely new snapshots (new inodes not seen before) and gone PIDs
// (previously cached PIDs that no longer exist).
//
// On steady-state ticks (no new pods, no exits), both return slices are
// empty — the tick becomes a near-zero-cost no-op (~40ms for 200 PIDs:
// one ReadDir + N Readlink + N Stat).
//
// Filtering (self-process, infrastructure processes) is applied here in
// the walker, not in individual scanner callbacks. This prevents wasted
// dispatching and eliminates duplicated filter logic across scanners.
func (pc *ProcCache) Diff() (newSnaps []ProcSnapshot, gonePIDs []uint32) {
	entries, err := os.ReadDir(ssl.ProcRoot)
	if err != nil {
		kg.Printf("ProcWalker: failed to read %s: %v", ssl.ProcRoot, err)
		return nil, nil
	}

	kg.Debugf("ProcWalker: scanning %d entries in %s", len(entries), ssl.ProcRoot)

	seen := make(map[uint32]struct{}, len(entries))

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var pid uint32
		if _, err := fmt.Sscanf(e.Name(), "%d", &pid); err != nil || pid <= 1 {
			continue
		}
		seen[pid] = struct{}{}

		// Filter: skip our own process to prevent self-instrumentation crashes.
		if ssl.IsSelfProcess(int(pid)) {
			continue
		}
		// Filter: skip known infrastructure processes (SPIRE, etc.)
		if ssl.IsInfraProcess(int(pid)) {
			continue
		}

		// Cheap readlink — one syscall.
		// IMPORTANT: /proc/<pid>/exe is a kernel "magic symlink" that resolves
		// correctly ONLY through the kernel's real procfs mount point.
		// Accessing it through a bind-mounted path (ssl.ProcRoot = /host/procfs)
		// causes ENOENT for every user-space process because the kernel does not
		// apply magic-symlink resolution across bind mounts.
		// With hostPID: true the container's /proc IS the host procfs, so we
		// use /proc directly here and only use ssl.ProcRoot for plain file reads
		// (e.g. /maps, /cgroup, /stat) where bind mounts work fine.
		exeLink := fmt.Sprintf("/proc/%d/exe", pid)
		exePath, err := os.Readlink(exeLink)
		if err != nil {
			// Kernel threads have no /exe symlink — this is normal and expected.
			// Only log at debug level to avoid flooding INFO logs.
			kg.Debugf("ProcWalker: PID %d readlink %s failed: %v (likely kernel thread)", pid, exeLink, err)
			continue
		}

		// Resolve through procfs root for containerised binaries.
		// We use native /proc directly instead of ssl.ProcRoot to avoid ebpf/link
		// failing with ENOENT when crossing the /host/procfs bind mount.
		hostPath := fmt.Sprintf("/proc/%d/root%s", pid, exePath)
		fi, err := os.Stat(hostPath)
		if err != nil {
			kg.Debugf("ProcWalker: PID %d stat %s failed: %v — using exe path", pid, hostPath, err)
			hostPath = exePath
			fi, err = os.Stat(hostPath)
		}
		if err != nil {
			kg.Printf("ProcWalker: PID %d stat final %s failed (%v) — yielding inode=0 snapshot", pid, hostPath, err)
			// Don't drop the PID: the sslScannerFunc can still discover SSL
			// libs for this process via /proc/<pid>/maps directly.
			// We skip inode-based dedup (inode=0) and rely on PID dedup only.
			pc.mu.RLock()
			_, alreadyKnown := pc.byPID[pid]
			pc.mu.RUnlock()
			if !alreadyKnown {
				newSnaps = append(newSnaps, ProcSnapshot{
					PID:      pid,
					ExePath:  exePath,
					HostPath: "",
					Inode:    0,
				})
			}
			continue
		}
		stat, ok := fi.Sys().(*syscall.Stat_t)
		if !ok {
			continue
		}
		inode := stat.Ino
		if inode == 0 {
			continue // stat failed to produce a valid inode
		}

		// Skip PIDs already in cache — we've already dispatched them.
		// Note: we track by PID (not inode) because each process needs its
		// own ssl_symaddrs BPF map entry (keyed by TGID). The inode is still
		// carried in the snapshot so individual scanners that attach uprobes
		// per-binary (Go HTTP/2, gRPC-C) can deduplicate on inode themselves.
		pc.mu.RLock()
		_, alreadyKnown := pc.byPID[pid]
		pc.mu.RUnlock()
		if alreadyKnown {
			continue
		}

		snap := ProcSnapshot{
			PID:      pid,
			ExePath:  exePath,
			HostPath: hostPath,
			Inode:    inode,
		}
		newSnaps = append(newSnaps, snap)
	}

	// Detect gone PIDs (for uprobe link cleanup on container exit).
	pc.mu.RLock()
	for pid := range pc.byPID {
		if _, alive := seen[pid]; !alive {
			gonePIDs = append(gonePIDs, pid)
		}
	}
	pc.mu.RUnlock()

	return newSnaps, gonePIDs
}

// Commit adds a snapshot to the cache. Called after all scanners have
// successfully processed the snapshot.
func (pc *ProcCache) Commit(snap ProcSnapshot) {
	pc.mu.Lock()
	pc.byPID[snap.PID] = snap
	if snap.Inode != 0 {
		pc.byInode[snap.Inode] = snap.PID
	}
	pc.mu.Unlock()
}

// Remove removes a PID from the cache (on process exit).
// Returns the snapshot that was removed, if any.
func (pc *ProcCache) Remove(pid uint32) (ProcSnapshot, bool) {
	pc.mu.Lock()
	defer pc.mu.Unlock()

	old, ok := pc.byPID[pid]
	if !ok {
		return ProcSnapshot{}, false
	}

	// Only remove the inode mapping if this PID was the one indexed.
	// Multiple PIDs can share the same inode (same binary, different containers).
	if old.Inode != 0 && pc.byInode[old.Inode] == pid {
		delete(pc.byInode, old.Inode)
	}
	delete(pc.byPID, pid)
	return old, true
}

// Size returns the number of tracked PIDs (for logging).
func (pc *ProcCache) Size() int {
	pc.mu.RLock()
	defer pc.mu.RUnlock()
	return len(pc.byPID)
}
