// SPDX-License-Identifier: Apache-2.0
// Copyright 2025 Authors of KubeArmor
package core

import (
	"slices"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

func (dm *KubeArmorDaemon) CreateEndpoint(endPoint *tp.EndPoint, container tp.Container, containerLabels map[string]string, containerIdentities []string, endPointEvent string) {
	switch endPointEvent {
	case "ADDED":
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
		// required only in ADDED event, this alone will update the namespaceList for csp
		updateNamespaceListforCSP(&secPol)

			// match ksp || csp
			if (kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(secPol.Spec.Selector, endPoint.Identities)) ||
				(kl.ContainsElement(secPol.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(secPol.Spec.Selector, endPoint.Identities)) {
				endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPol)
			}
		}
		dm.SecurityPoliciesLock.RUnlock()

		dm.EndPoints = append(dm.EndPoints, *endPoint)
	case "UPDATED":
		// in case of AppArmor enforcement when endPoint has to be created first
		endPoint.Containers = append(endPoint.Containers, container.ContainerID)

		// if this container has any additional identities, add them
		endPoint.Identities = append(endPoint.Identities, containerIdentities...)
		endPoint.Identities = slices.Compact(endPoint.Identities)

		// add other policies
		endPoint.SecurityPolicies = []tp.SecurityPolicy{}
		dm.SecurityPoliciesLock.RLock()
		for _, secPol := range dm.SecurityPolicies {
			if kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) {
				endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPol)
			}
		}
		dm.SecurityPoliciesLock.RUnlock()
	}
}

func (dm *KubeArmorDaemon) PopulateMaps(endPoint tp.EndPoint, container tp.Container) {
	// for throttling
	dm.SystemMonitor.Logger.ContainerNsKey[container.ContainerID] = kl.OuterKey{
		MntNs: container.MntNS,
		PidNs: container.PidNS,
	}

	// update NsMap
	dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
	dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
	if dm.Presets != nil {
		dm.Presets.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
	}

	if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endPoint yet
		dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
		if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// enforce security policies
			dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
		}
		if dm.Presets != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// enforce preset rules
			dm.Presets.UpdateSecurityPolicies(endPoint)
		}
	}
}

func (dm *KubeArmorDaemon) HandleContainerCreateForKata(container tp.Container) {
	endPoint := tp.EndPoint{}

	dm.ContainersLock.Lock()
	defer dm.ContainersLock.Unlock()
	if _, ok := dm.Containers[container.ContainerID]; !ok {
		dm.Containers[container.ContainerID] = container

		// create/update endpoint in non-k8s mode
		if !dm.K8sEnabled {
			// for policy matching
			container.NamespaceName = "container_namespace"
			labels := []string{}
			labels = append(labels, "namespaceName="+container.NamespaceName)
			labels = append(labels, "kubearmor.io/container.name="+container.ContainerName)
			container.Labels = strings.Join(labels, ",")

			containerLabels, containerIdentities := kl.GetLabelsFromString(container.Labels)
			dm.EndPointsLock.Lock()
			dm.CreateEndpoint(&endPoint, container, containerLabels, containerIdentities, "ADDED")
			dm.EndPointsLock.Unlock()
		}
	} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
		c := dm.Containers[container.ContainerID]
		c.MntNS = container.MntNS
		c.PidNS = container.PidNS
		c.AppArmorProfile = container.AppArmorProfile
		dm.Containers[c.ContainerID] = c

		dm.EndPointsLock.Lock()
		for idx, endpoint := range dm.EndPoints {
			if endpoint.NamespaceName == container.NamespaceName && endpoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				if !kl.ContainsElement(endpoint.AppArmorProfiles, container.AppArmorProfile) {
					dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
				}

				if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
					dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
				}

				endPoint = dm.EndPoints[idx]

				break
			}
		}
		dm.EndPointsLock.Unlock()
	}

	if len(dm.OwnerInfo) > 0 {
		container.Owner = dm.OwnerInfo[container.EndPointName]
	}

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.PopulateMaps(endPoint, container)
	}

	if cfg.GlobalCfg.StateAgent {
		container.Status = "running"
		go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
	}

	dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
}
