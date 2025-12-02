//go:build windows

// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package presets contains preset rules components
package presets

import (
	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// NewPreset [unsupported on windows]
func NewPreset(_ *fd.Feeder, _ *mon.SystemMonitor) *Preset {
	return nil
}

// RegisterPresets [unsupported on windows]
func (p *Preset) RegisterPresets() {
}

// RegisterContainer [unsupported on windows]
func (p *Preset) RegisterContainer(_ string, _, _ uint32) {
}

// UnregisterContainer [unsupported on windows]
func (p *Preset) UnregisterContainer(_ string) {
}

// UpdateSecurityPolicies Function [unsupported on windows]
func (p *Preset) UpdateSecurityPolicies(_ tp.EndPoint) {
}

// Destroy Function [unsupported on windows]
func (p *Preset) Destroy() error {
	return nil
}
