// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// UpdatePodmanContainer Function
func (dm *KubeArmorDaemon) UpdatePodmanContainer(containerID string, container tp.Container, action string) bool {

	if action == "create" {

		if container.ContainerID == "" {
			return false
		}

		endPoint := tp.EndPoint{}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()

			containerLabels, containerIdentities := common.GetLabelsFromString(container.Labels)
			dm.EndPointsLock.Lock()

			endPoint.EndPointName = container.ContainerName
			endPoint.ContainerName = container.ContainerName
			endPoint.NamespaceName = container.NamespaceName
			endPoint.Containers = []string{container.ContainerID}
			endPoint.Labels = containerLabels
			endPoint.Identities = containerIdentities
			endPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
			endPoint.ProcessVisibilityEnabled = true
			endPoint.FileVisibilityEnabled = true
			endPoint.NetworkVisibilityEnabled = true
			endPoint.CapabilitiesVisibilityEnabled = true

			endPoint.AppArmorProfiles = []string{"kubearmor_" + container.ContainerName}

			globalDefaultPosture := tp.DefaultPosture{
				FileAction:         cfg.GlobalCfg.DefaultFilePosture,
				NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
				CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
			}
			endPoint.DefaultPosture = globalDefaultPosture

			dm.SecurityPoliciesLock.RLock()
			for _, secPol := range dm.SecurityPolicies {				
				if kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) {
					endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPol)
				}
			}
			dm.SecurityPoliciesLock.RUnlock()

			dm.EndPoints = append(dm.EndPoints, endPoint)
			dm.EndPointsLock.Unlock()

		} else {
			dm.ContainersLock.Unlock()
			return false
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// for throttling
			dm.SystemMonitor.Logger.ContainerNsKey[containerID] = common.OuterKey{
				MntNs: container.MntNS,
				PidNs: container.PidNS,
			}

			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(containerID, container.PidNS, container.MntNS)


			if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endPoint yet
				dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
				if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					dm.Logger.Printf("Enforcing security policies for container ID %s",containerID)
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
				}
			}
		}

		if cfg.GlobalCfg.StateAgent {
			container.Status = "running"
			go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
		}

		dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)

	} else if action == "destroy" {
		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return false
		}
		dm.EndPointsLock.Lock()
		dm.MatchandRemoveContainerFromEndpoint(containerID)
		dm.EndPointsLock.Unlock()
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

		dm.EndPointsLock.Lock()
		// remove apparmor profile for that endpoint
		for idx, endPoint := range dm.EndPoints {
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				for idxA, profile := range endPoint.AppArmorProfiles {
					if profile == container.AppArmorProfile {
						dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles[:idxA], dm.EndPoints[idx].AppArmorProfiles[idxA+1:]...)
						break
					}
				}

				break
			}
		}
		dm.EndPointsLock.Unlock()
		// delete endpoint if no security rules and containers
		idx := 0
		endpointsLength := len(dm.EndPoints)
		for idx < endpointsLength {
			endpoint := dm.EndPoints[idx]
			if container.NamespaceName == endpoint.NamespaceName && container.ContainerName == endpoint.EndPointName &&
				len(endpoint.SecurityPolicies) == 0 && len(endpoint.Containers) == 0 {
				dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)
				endpointsLength--
				idx--
			}
			idx++
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			outkey := dm.SystemMonitor.Logger.ContainerNsKey[containerID]
			dm.Logger.DeleteAlertMapKey(outkey)
			delete(dm.SystemMonitor.Logger.ContainerNsKey, containerID)
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
		}

		if cfg.GlobalCfg.StateAgent {
			container.Status = "terminated"
			go dm.StateAgent.PushContainerEvent(container, state.EventDeleted)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)
	}

	return true
}
