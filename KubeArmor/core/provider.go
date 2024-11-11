package core

import (
	"slices"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
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
			if kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) {
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
	dm.SystemMonitor.Logger.ContainerNsKey[container.ContainerID] = common.OuterKey{
		MntNs: container.MntNS,
		PidNs: container.PidNS,
	}

	// update NsMap
	dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
	dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)

	if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endPoint yet
		dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
		if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// enforce security policies
			dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
		}
	}
}
