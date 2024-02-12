package presets

import (
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

type Preset struct {
	BasePreset

	List map[string]BasePresetInterface
}

// RegisterPresets initiates and adds presets to map
func (p *Preset) RegisterPresets() {
	for _, v := range p.List {
		v.RegisterPreset(p.Logger, p.Monitor)
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
