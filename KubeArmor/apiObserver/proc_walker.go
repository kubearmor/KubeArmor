// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package apiobserver

import (
	"context"
	"time"

	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
)

// ScannerFunc is a callback that processes a newly discovered process.
// Each scanner (SSL, Go HTTP/2, gRPC-C) registers one of these.
// The function receives a ProcSnapshot for a PID whose binary inode
// has never been seen before. It should read only the /proc files it
// needs (e.g. maps, cgroup) and attach probes as appropriate.
//
// Errors are logged but do not prevent other scanners from running.
type ScannerFunc func(snap ProcSnapshot) error

// GonePIDFunc is called when a previously cached PID is no longer alive.
// Used for uprobe link cleanup on container exit.
type GonePIDFunc func(pid uint32, snap ProcSnapshot)

// UnifiedProcWalker replaces three independent 30s /proc walkers (SSL,
// Go HTTP/2, gRPC-C) with a single walker that diffs against a ProcCache.
//
// On steady-state ticks (no new pods, no exits), Diff() returns empty
// slices and tick() returns immediately — a near-zero-cost no-op.
//
// The walker is staggered 10s from startup to let BPF attachment settle.
type UnifiedProcWalker struct {
	interval time.Duration
	stagger  time.Duration
	cache    *ProcCache
	scanners []ScannerFunc
	onGone   GonePIDFunc
}

// NewUnifiedProcWalker creates a walker with the given interval and scanners.
// The default interval is 20s — cheap enough with inode caching that even
// 10s would be safe, but 20s matches typical Kubernetes pod startup latency.
func NewUnifiedProcWalker(interval time.Duration, scanners []ScannerFunc, onGone GonePIDFunc) *UnifiedProcWalker {
	return &UnifiedProcWalker{
		interval: interval,
		stagger:  10 * time.Second,
		cache:    NewProcCache(),
		scanners: scanners,
		onGone:   onGone,
	}
}

// Run starts the walker loop. It blocks until ctx is cancelled.
// Call from a goroutine: go walker.Run(ctx)
func (w *UnifiedProcWalker) Run(ctx context.Context) {
	// Stagger from startup — let BPF attach, ring buffer readers, and
	// other tickers settle before the first /proc walk.
	select {
	case <-time.After(w.stagger):
	case <-ctx.Done():
		return
	}

	// Initial scan — processes everything currently running.
	w.tick(ctx)

	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			w.tick(ctx)
		case <-ctx.Done():
			return
		}
	}
}

// tick performs one scan cycle: diff, dispatch new snapshots to scanners,
// handle gone PIDs, commit to cache.
func (w *UnifiedProcWalker) tick(ctx context.Context) {
	newSnaps, gonePIDs := w.cache.Diff()

	// Steady-state: nothing new, nothing gone → return immediately.
	if len(newSnaps) == 0 && len(gonePIDs) == 0 {
		return
	}

	if len(newSnaps) > 0 {
		kg.Debugf("ProcWalker: %d new snapshots to process", len(newSnaps))
	}
	if len(gonePIDs) > 0 {
		kg.Debugf("ProcWalker: %d PIDs exited", len(gonePIDs))
	}

	// Process new snapshots — dispatch to all registered scanners.
	for _, snap := range newSnaps {
		// Allow fast exit during shutdown.
		select {
		case <-ctx.Done():
			return
		default:
		}

		for _, scanner := range w.scanners {
			if err := scanner(snap); err != nil {
				kg.Warnf("ProcWalker: scanner error for PID %d: %v", snap.PID, err)
			}
		}

		// Commit to cache only after all scanners have processed.
		// This ensures that if a scanner fails, the PID will be
		// retried on the next tick.
		w.cache.Commit(snap)
	}

	// Handle gone PIDs — close uprobe links for exited containers.
	for _, pid := range gonePIDs {
		if snap, ok := w.cache.Remove(pid); ok && w.onGone != nil {
			w.onGone(pid, snap)
		}
	}

	kg.Debugf("ProcWalker: tick complete, cache size=%d", w.cache.Size())
}

// Cache returns the underlying ProcCache for direct access (e.g. testing).
func (w *UnifiedProcWalker) Cache() *ProcCache {
	return w.cache
}
