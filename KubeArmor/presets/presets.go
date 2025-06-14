// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package presets contains preset rules components
package presets

import (
	"errors"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	anonmap "github.com/kubearmor/KubeArmor/KubeArmor/presets/anonmapexec"
	"github.com/kubearmor/KubeArmor/KubeArmor/presets/base"
	exec "github.com/kubearmor/KubeArmor/KubeArmor/presets/exec"
	filelessexec "github.com/kubearmor/KubeArmor/KubeArmor/presets/filelessexec"
	protectenv "github.com/kubearmor/KubeArmor/KubeArmor/presets/protectenv"
	protectproc "github.com/kubearmor/KubeArmor/KubeArmor/presets/protectproc"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// Preset struct
type Preset struct {
	base.Preset

	List map[string]base.PresetInterface
}

// NewPreset returns an instance of Preset
func NewPreset(logger *fd.Feeder, monitor *mon.SystemMonitor) *Preset {
	p := &Preset{}

	p.List = make(map[string]base.PresetInterface)
	p.Logger = logger
	p.Monitor = monitor

	// add all presets
	p.List[anonmap.NAME] = anonmap.NewAnonMapExecPreset()
	p.List[filelessexec.NAME] = filelessexec.NewFilelessExecPreset()
	p.List[protectenv.NAME] = protectenv.NewProtectEnvPreset()
	p.List[exec.NAME] = exec.NewExecPreset()
	p.List[protectproc.NAME] = protectproc.NewProtectProcPreset()

	// register all presets
	p.RegisterPresets()

	if len(p.List) > 0 {
		return p
	}
	return nil
}

// RegisterPresets initiates and adds presets to map
func (p *Preset) RegisterPresets() {
	for k, v := range p.List {
		_, err := v.RegisterPreset(p.Logger, p.Monitor)
		if err != nil {
			delete(p.List, k)
		}
	}
}

// RegisterContainer registers container identifiers
func (p *Preset) RegisterContainer(containerID string, pidns, mntns uint32) {
	for _, v := range p.List {
		v.RegisterContainer(containerID, pidns, mntns)
	}
}

// UnregisterContainer removes container identifiers
func (p *Preset) UnregisterContainer(containerID string) {
	for _, v := range p.List {
		v.UnregisterContainer(containerID)
	}
}

// UpdateSecurityPolicies Function
func (p *Preset) UpdateSecurityPolicies(endPoint tp.EndPoint) {
	for _, v := range p.List {
		v.UpdateSecurityPolicies(endPoint)
	}
}

// Destroy Function
func (p *Preset) Destroy() error {
	var destroyErr error
	for _, v := range p.List {
		err := v.Destroy()
		if err != nil {
			destroyErr = errors.Join(destroyErr, err)
		}
	}
	return destroyErr
}
