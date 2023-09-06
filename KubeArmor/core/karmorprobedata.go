// SPDX-License-Identifier: Apache-2.0
// Copyright 2022 Authors of KubeArmor

package core

import (
	"context"

	"github.com/golang/protobuf/ptypes/empty"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
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

// Karmor provides structure to serve Policy gRPC service
type Karmor struct {
	pb.KarmorServer
	GetContainerData func() ([]string, map[string]*pb.ContainerData, map[string]*pb.HostSecurityPolicies)
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

// SetKarmorContainerData() keeps track of containers and the applied policies
func (dm *KubeArmorDaemon) SetKarmorContainerData() ([]string, map[string]*pb.ContainerData, map[string]*pb.HostSecurityPolicies) {
	var containerlist []string
	dm.ContainersLock.Lock()
	for _, value := range dm.Containers {

		containerlist = append(containerlist, value.ContainerName)
	}
	dm.ContainersLock.Unlock()

	containerMap := make(map[string]*pb.ContainerData)
	dm.EndPointsLock.Lock()

	for _, ep := range dm.EndPoints {

		var policyNames []string

		for _, policy := range ep.SecurityPolicies {

			policyNames = append(policyNames, policy.Metadata["policyName"])

		}
		containerMap[ep.EndPointName] = &pb.ContainerData{
			PolicyList:    policyNames,
			PolicyEnabled: int32(ep.PolicyEnabled),
		}
	}
	dm.EndPointsLock.Unlock()

	// Mapping Hostpolicies to their host hostName : HostPolicy
	hostMap := make(map[string]*pb.HostSecurityPolicies)

	dm.HostSecurityPoliciesLock.Lock()
	for _, hp := range dm.HostSecurityPolicies {

		hostName := ""
		for _, v := range hp.Spec.NodeSelector.MatchLabels {
			hostName = v
		}
		if val, ok := hostMap[hostName]; ok {

			val.PolicyList = append(val.PolicyList, hp.Metadata["policyName"])
			hostMap[hostName] = val

		} else {

			hostMap[hostName] = &pb.HostSecurityPolicies{
				PolicyList: []string{hp.Metadata["policyName"]},
			}

		}
	}
	dm.HostSecurityPoliciesLock.Unlock()

	return containerlist, containerMap, hostMap

}

// GetKarmorData() sends policy data through grpc client
func (p *Karmor) GetKarmorData(c context.Context, in *empty.Empty) (*pb.Karmorresponse, error) {

	var containerMap map[string]*pb.ContainerData

	containerList, containerMap, hostMap := p.GetContainerData()
	res := &pb.Karmorresponse{
		ContainerList: containerList,
		ContainerMap:  containerMap,
		HostMap:       hostMap,
	}

	return res, nil

}
