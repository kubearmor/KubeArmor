// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package presets

import (
	"errors"

	fd "github.com/kubearmor/KubeArmor/KubeArmor/feeder"
	mon "github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	"github.com/kubearmor/KubeArmor/KubeArmor/presets/base"
	fileless "github.com/kubearmor/KubeArmor/KubeArmor/presets/filelessexec"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type Preset struct {
	base.BasePreset

	List map[string]base.BasePresetInterface
}

func NewPreset(logger *fd.Feeder, monitor *mon.SystemMonitor) *Preset {
	p := &Preset{}

	p.List = make(map[string]base.BasePresetInterface)
	p.Logger = logger
	p.Monitor = monitor

	// add all presets
	p.List[fileless.NAME] = fileless.NewFilelessExecPreset()

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
