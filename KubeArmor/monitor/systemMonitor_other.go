// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

package monitor

// initBPFMaps is a no-op on non-Linux platforms, where BPF maps cannot be created.
func (mon *SystemMonitor) initBPFMaps() error {
	return nil
}

// InitBPF is a no-op on non-Linux platforms. The eBPF system monitor (maps,
// programs, kprobes, perf reader) is unavailable, so the daemon runs without
// syscall/event tracing.
func (mon *SystemMonitor) InitBPF() error {
	mon.Logger.Print("eBPF system monitor is unavailable on this platform; skipping")
	return nil
}

// DestroyBPFMaps is a no-op on non-Linux platforms.
func (mon *SystemMonitor) DestroyBPFMaps() {}
