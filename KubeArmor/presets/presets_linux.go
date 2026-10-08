// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

//go:build linux

// Package presets contains preset rules components
package presets

import (
	anonmap "github.com/kubearmor/KubeArmor/KubeArmor/presets/anonmapexec"
	exec "github.com/kubearmor/KubeArmor/KubeArmor/presets/exec"
	filelessexec "github.com/kubearmor/KubeArmor/KubeArmor/presets/filelessexec"
	protectenv "github.com/kubearmor/KubeArmor/KubeArmor/presets/protectenv"
	protectproc "github.com/kubearmor/KubeArmor/KubeArmor/presets/protectproc"
)

// addPresets populates p.List with all eBPF-backed presets.
func (p *Preset) addPresets() {
	p.List[anonmap.NAME] = anonmap.NewAnonMapExecPreset()
	p.List[filelessexec.NAME] = filelessexec.NewFilelessExecPreset()
	p.List[protectenv.NAME] = protectenv.NewProtectEnvPreset()
	p.List[exec.NAME] = exec.NewExecPreset()
	p.List[protectproc.NAME] = protectproc.NewProtectProcPreset()
}
