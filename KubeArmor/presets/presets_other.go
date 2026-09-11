// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build !linux

// Package presets contains preset rules components
package presets

// addPresets is a no-op on non-Linux platforms, where the eBPF-backed presets are
// not compiled in. NewPreset consequently returns nil and presets are disabled.
func (p *Preset) addPresets() {}
