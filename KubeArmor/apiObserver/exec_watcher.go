// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// exec_watcher.go — Exec-triggered SSL uprobe attachment.
//
// ExecWatcher reads ka_found_pid_events from the BPF perf ring (produced by
// ka_sched_process_fork + ka_kretprobe_sys_execve in exec_trace.h). For each
// event it immediately calls sslScannerFunc for the newly exec'd process —
// the same function the UnifiedProcWalker uses on its 20s ticks.
//
// This catches ephemeral processes (curl, wget) that start and exit between
// walker ticks, without duplicating any attachment or deduplication logic.
//
// Two paths, one function:
//
//	UnifiedProcWalker (20s tick) ──► sslScannerFunc(snap)  — long-lived procs
//	ExecWatcher (BPF event)      ──► sslScannerFunc(snap)  — ephemeral procs
package apiobserver

import (
	"context"
	"encoding/binary"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/perf"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
)

// kaFoundPid mirrors BPF struct ka_found_pid (exec_trace.h).
// Field layout must match the C struct exactly.
//
//	struct ka_found_pid { __u64 cgroup_id; __u32 tgid; __u32 __pad; };
type kaFoundPid struct {
	CgroupID uint64
	Tgid     uint32
	_        uint32 // __pad — not used in Go
}

// ExecWatcher reads BPF exec events and calls sslScannerFunc immediately
// when a new process exec's. A bounded worker pool (numWorkers goroutines)
// processes events so a fork-bomb cannot spawn unbounded goroutines.
type ExecWatcher struct {
	perfReader  *perf.Reader
	scannerFunc ScannerFunc // ao.sslScannerFunc
	logger      *fd.Feeder
	jobs        chan uint32 // bounded job queue (capacity 256)
	wg          sync.WaitGroup
}

// NewExecWatcher creates an ExecWatcher backed by the ka_found_pid_events BPF map.
// scannerFunc should be ao.sslScannerFunc — the same callback used by the proc walker.
func NewExecWatcher(
	perfMap *ebpf.Map,
	scannerFunc ScannerFunc,
	logger *fd.Feeder,
) (*ExecWatcher, error) {
	pr, err := perf.NewReader(perfMap, 256*1024) // 256 KB per-CPU ring
	if err != nil {
		return nil, err
	}
	return &ExecWatcher{
		perfReader:  pr,
		scannerFunc: scannerFunc,
		logger:      logger,
		jobs:        make(chan uint32, 256),
	}, nil
}

// Stop closes the perf reader, causing the read loop in Start to exit.
func (w *ExecWatcher) Stop() error {
	return w.perfReader.Close()
}

// Start reads exec events from the BPF perf ring until ctx is cancelled or
// the reader is closed. Uses a bounded worker pool to prevent unbounded
// goroutine creation during container restart storms.
// Run as a goroutine: go w.Start(ctx)
func (w *ExecWatcher) Start(ctx context.Context) {
	// Close the perf reader when context is cancelled to unblock Read().
	go func() {
		<-ctx.Done()
		_ = w.perfReader.Close()
	}()

	// Start a fixed-size worker pool that drains the job channel.
	const numWorkers = 4
	for i := 0; i < numWorkers; i++ {
		w.wg.Add(1)
		go func() {
			defer w.wg.Done()
			for pid := range w.jobs {
				w.handleExec(ctx, pid)
			}
		}()
	}

	// Read loop: dispatch events to the worker pool via non-blocking send.
	for {
		rec, err := w.perfReader.Read()
		if err != nil {
			// perf.ErrClosed is the normal shutdown path.
			break
		}
		if len(rec.RawSample) < 12 {
			continue
		}

		var fp kaFoundPid
		fp.CgroupID = binary.LittleEndian.Uint64(rec.RawSample[0:8])
		fp.Tgid = binary.LittleEndian.Uint32(rec.RawSample[8:12])

		w.logger.Debugf("[ExecWatcher] exec event: tgid=%d cgroupID=%d", fp.Tgid, fp.CgroupID)

		// Non-blocking dispatch: drop if the job queue is full.
		select {
		case w.jobs <- fp.Tgid:
		default:
			w.logger.Debugf("[ExecWatcher] job queue full, dropping tgid=%d", fp.Tgid)
		}
	}

	// Signal workers to stop and wait for them to finish.
	close(w.jobs)
	w.wg.Wait()
}

// handleExec calls sslScannerFunc for the newly exec'd PID — identical to what
// the UnifiedProcWalker does, just triggered immediately instead of after up to 20s.
func (w *ExecWatcher) handleExec(ctx context.Context, pid uint32) {
	select {
	case <-ctx.Done():
		return
	default:
	}

	// Build a minimal ProcSnapshot — sslScannerFunc only uses snap.PID.
	snap := ProcSnapshot{PID: pid}
	if err := w.scannerFunc(snap); err != nil {
		w.logger.Warnf("[ExecWatcher] pid=%d: sslScannerFunc error: %v", pid, err)
	}
}
