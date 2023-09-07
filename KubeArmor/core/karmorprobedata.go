// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// KarmorData Structure
type KarmorData struct {
	OSImage                 string
	KernelVersion           string
	KubeletVersion          string
	ContainerRuntime        string
	ActiveLSM               string
	KernelHeaderPresent     bool
	HostSecurity            bool
	ContainerSecurity       bool
	ContainerDefaultPosture tp.DefaultPosture
	HostDefaultPosture      tp.DefaultPosture
	HostVisibility          string
}

// SetKarmorData generates runtime configuration for KubeArmor to be consumed by kArmor
func (dm *KubeArmorDaemon) SetKarmorData() {
	var kd KarmorData

	kd.ContainerDefaultPosture = tp.DefaultPosture{
		FileAction:         cfg.GlobalCfg.DefaultFilePosture,
		NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
		CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
	}
	kd.HostDefaultPosture = tp.DefaultPosture{
		FileAction:         cfg.GlobalCfg.HostDefaultFilePosture,
		NetworkAction:      cfg.GlobalCfg.HostDefaultNetworkPosture,
		CapabilitiesAction: cfg.GlobalCfg.HostDefaultCapabilitiesPosture,
	}

	kd.OSImage = dm.Node.OSImage
	kd.ContainerRuntime = dm.Node.ContainerRuntimeVersion
	kd.KernelVersion = dm.Node.KernelVersion
	kd.KubeletVersion = dm.Node.KubeletVersion
	kd.ContainerRuntime = dm.Node.ContainerRuntimeVersion
	if dm.RuntimeEnforcer != nil {
		kd.ActiveLSM = dm.RuntimeEnforcer.EnforcerType

		if cfg.GlobalCfg.Policy {
			kd.ContainerSecurity = true
		}
		if cfg.GlobalCfg.HostPolicy {
			kd.HostSecurity = true
		}
	}
	kd.KernelHeaderPresent = true //this is always true since KubeArmor is running
	kd.HostVisibility = dm.Node.Annotations["kubearmor-visibility"]
	err := kl.WriteToFile(kd, "/tmp/karmorProbeData.cfg")
	if err != nil {
		dm.Logger.Errf("Error writing karmor config data (%s)", err.Error())
	}

}
