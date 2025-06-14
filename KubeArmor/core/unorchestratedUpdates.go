// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package core

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"

	"github.com/fsnotify/fsnotify"
	"github.com/spf13/viper"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// SetContainerVisibility function enables visibility flag arguments for un-orchestrated container and updates the visibility map
func (dm *KubeArmorDaemon) SetContainerNSVisibility() {

	visibility := tp.Visibility{}

	if strings.Contains(cfg.GlobalCfg.Visibility, "process") {
		visibility.Process = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "file") {
		visibility.File = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "network") {
		visibility.Network = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "capabilities") {
		visibility.Capabilities = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "dns") {
		visibility.DNS = true
	}

	dm.UpdateVisibility("ADDED", "container_namespace", visibility)
}

// =================== //
// == Config Update == //
// =================== //

// WatchConfigChanges watches for configuration changes and updates the default posture
func (dm *KubeArmorDaemon) WatchConfigChanges() {
	viper.OnConfigChange(func(e fsnotify.Event) {
		dm.Logger.Printf("Config file changed: %s", e.Name)
		cfg.LoadDynamicConfig()

		// Update the default posture
		globalPosture := tp.DefaultPosture{
			FileAction:         validateGlobalDefaultPosture(cfg.GlobalCfg.DefaultFilePosture),
			NetworkAction:      validateGlobalDefaultPosture(cfg.GlobalCfg.DefaultNetworkPosture),
			CapabilitiesAction: validateGlobalDefaultPosture(cfg.GlobalCfg.DefaultCapabilitiesPosture),
		}
		// Update the visibility
		visibility := tp.Visibility{
			File:         dm.validateVisibility("file", cfg.GlobalCfg.Visibility),
			Process:      dm.validateVisibility("process", cfg.GlobalCfg.Visibility),
			Network:      dm.validateVisibility("network", cfg.GlobalCfg.Visibility),
			Capabilities: dm.validateVisibility("capabilities", cfg.GlobalCfg.Visibility),
			DNS:          dm.validateVisibility("dns", cfg.GlobalCfg.Visibility),
		}

		// Apply the changes to the daemon
		dm.UpdateGlobalPosture(globalPosture)

		// Update default posture for endpoints
		for _, ep := range dm.EndPoints {
			dm.Logger.Printf("Updating Default Posture for endpoint %s", ep.EndPointName)
			dm.UpdateDefaultPosture("MODIFIED", ep.NamespaceName, globalPosture, false)
			dm.UpdateVisibility("MODIFIED", ep.NamespaceName, visibility)
		}

		// Update throttling configs
		dm.SystemMonitor.UpdateThrottlingConfig()

		// Update the default posture and visibility for the unorchestrated containers
		dm.SystemMonitor.UpdateVisibility()
		dm.UpdateHostSecurityPolicies()
	})
	viper.WatchConfig()
}

// ====================================== //
// == Container Security Policy Update == //
// ====================================== //

// MatchandUpdateContainerSecurityPolicies finds relevant endpoint for containers and updates the security policies for enforcement
func (dm *KubeArmorDaemon) MatchandUpdateContainerSecurityPolicies(cid string) {
	container := dm.Containers[cid]
	for idx, ep := range dm.EndPoints {
		_, containerIdentities := kl.GetLabelsFromString(container.Labels)
		if ep.EndPointName == dm.Containers[cid].ContainerName || kl.MatchIdentities(ep.Identities, containerIdentities) {
			ep.Containers = append(ep.Containers, cid)
			dm.EndPoints[idx] = ep
			ctr := dm.Containers[cid]
			ctr.NamespaceName = ep.NamespaceName
			ctr.EndPointName = ep.EndPointName
			dm.Containers[cid] = ctr
			if cfg.GlobalCfg.Policy {
				// update security policies
				dm.Logger.UpdateSecurityPolicies("MODIFIED", ep)
				if ep.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					if dm.RuntimeEnforcer != nil {
						// enforce security policies
						dm.RuntimeEnforcer.UpdateSecurityPolicies(ep)
					}
					if dm.Presets != nil {
						dm.Presets.UpdateSecurityPolicies(ep)
					}
				}
			}
		}
	}
}

// MatchandRemoveContainerSecurityPolicies finds relevant endpoint for containers and removes cid from the container list
func (dm *KubeArmorDaemon) MatchandRemoveContainerFromEndpoint(cid string) {
	container := dm.Containers[cid]
	for idx, ep := range dm.EndPoints {
		_, containerIdentities := kl.GetLabelsFromString(container.Labels)
		if ep.EndPointName == container.ContainerName || kl.MatchIdentities(ep.Identities, containerIdentities) {
			for i, c := range ep.Containers {
				if c != cid {
					continue
				}
				ep.Containers = append(ep.Containers[:i], ep.Containers[i+1:]...)
				break
			}
		}
		dm.EndPoints[idx] = ep
	}
}

func (dm *KubeArmorDaemon) handlePolicyEvent(eventType string, createEndPoint bool, secPolicy tp.SecurityPolicy, newPoint tp.EndPoint, endpointIdx int, containername string) (int, pb.PolicyStatus) {
	if containername == "" {
		containername = newPoint.ContainerName
	}

	appArmorAnnotations := map[string]string{}
	appArmorAnnotations[containername] = "kubearmor_" + containername

	globalDefaultPosture := tp.DefaultPosture{
		FileAction:         cfg.GlobalCfg.DefaultFilePosture,
		NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
		CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
	}
	newPoint.DefaultPosture = globalDefaultPosture

	// check that a security policy should exist before performing delete operation
	policymatch := 0
	for _, policy := range newPoint.SecurityPolicies {
		// check if policy exist
		if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
			policymatch = 1 // policy exists
		}
	}

	// policy doesn't exist and the policy is being removed
	if policymatch == 0 && eventType == "DELETED" {
		dm.Logger.Warnf("Failed to delete security policy. Policy doesn't exist")
		return endpointIdx, pb.PolicyStatus_NotExist
	}

	for idx, policy := range newPoint.SecurityPolicies {
		if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
			if eventType == "DELETED" {
				newPoint.SecurityPolicies = append(newPoint.SecurityPolicies[:idx], newPoint.SecurityPolicies[idx+1:]...)
				break
			} else {
				// Policy already exists so modify
				eventType = "MODIFIED"
				newPoint.SecurityPolicies[idx] = secPolicy
			}
		}
	}

	var privilegedProfiles map[string]struct{}
	if eventType == "ADDED" {
		dm.RuntimeEnforcer.UpdateAppArmorProfiles(containername, "ADDED", appArmorAnnotations, privilegedProfiles)

		newPoint.SecurityPolicies = append(newPoint.SecurityPolicies, secPolicy)
		if createEndPoint {
			// Create new EndPoint - possible scenarios:
			// policy received before container
			newPoint.NamespaceName = secPolicy.Metadata["namespaceName"]
			newPoint.EndPointName = containername
			newPoint.ContainerName = containername
			newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
			newPoint.Identities = secPolicy.Spec.Selector.Identities

			newPoint.ProcessVisibilityEnabled = true
			newPoint.FileVisibilityEnabled = true
			newPoint.NetworkVisibilityEnabled = true
			newPoint.CapabilitiesVisibilityEnabled = true
			newPoint.Containers = []string{}

			newPoint.PrivilegedContainers = map[string]struct{}{}

			newPoint.AppArmorProfiles = []string{"kubearmor_" + containername}

			// add the endpoint into the endpoint list
			dm.EndPoints = append(dm.EndPoints, newPoint)
		} else {
			dm.EndPoints[endpointIdx] = newPoint
		}

		if cfg.GlobalCfg.Policy {
			// update security policies
			dm.Logger.UpdateSecurityPolicies("ADDED", newPoint)

			if newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				if dm.RuntimeEnforcer != nil {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
				}
				if dm.Presets != nil {
					dm.Presets.UpdateSecurityPolicies(newPoint)
				}
			}
		}
	} else if eventType == "MODIFIED" {
		dm.EndPoints[endpointIdx] = newPoint
		if cfg.GlobalCfg.Policy {
			// update security policies
			dm.Logger.UpdateSecurityPolicies("MODIFIED", newPoint)

			if newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				if dm.RuntimeEnforcer != nil {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
				}
				if dm.Presets != nil {
					// enforce preset rules
					dm.Presets.UpdateSecurityPolicies(newPoint)
				}
			}
		}
	} else { // DELETED
		// update security policies after policy deletion
		if endpointIdx >= 0 {
			dm.EndPoints[endpointIdx] = newPoint
			dm.Logger.UpdateSecurityPolicies("DELETED", newPoint)
			dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
			if dm.Presets != nil {
				dm.Presets.UpdateSecurityPolicies(newPoint)
			}
			// delete endpoint if no containers or policies
			if len(newPoint.Containers) == 0 && len(newPoint.SecurityPolicies) == 0 {
				dm.EndPoints = append(dm.EndPoints[:endpointIdx], dm.EndPoints[endpointIdx+1:]...)
				// since the length of endpoints slice reduced
				endpointIdx--
			}
		}
	}

	return endpointIdx, pb.PolicyStatus_Applied
}

// ParseAndUpdateContainerSecurityPolicy Function
func (dm *KubeArmorDaemon) ParseAndUpdateContainerSecurityPolicy(event tp.K8sKubeArmorPolicyEvent) pb.PolicyStatus {

	// create a container security policy
	secPolicy := tp.SecurityPolicy{}

	secPolicy.Metadata = map[string]string{}
	secPolicy.Metadata["namespaceName"] = "container_namespace" //event.Object.Metadata.Namespace
	secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

	if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
		dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
		return pb.PolicyStatus_Failure
	}

	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Network.MatchProtocols)
	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Capabilities.MatchCapabilities)

	switch secPolicy.Spec.Action {
	case "allow":
		secPolicy.Spec.Action = "Allow"
	case "audit":
		secPolicy.Spec.Action = "Audit"
	case "block":
		secPolicy.Spec.Action = "Block"
	case "":
		secPolicy.Spec.Action = "Block" // by default
	}

	// add identities
	if len(secPolicy.Spec.Selector.MatchLabels) == 0 {
		dm.Logger.Warnf("Failed to apply policy. No labels to match found on policy.")
		return pb.PolicyStatus_Invalid
	}

	// can't use the container name label and label selectors at the same time
	if _, ok := secPolicy.Spec.Selector.MatchLabels["kubearmor.io/container.name"]; ok && len(secPolicy.Spec.Selector.MatchLabels) > 1 {
		dm.Logger.Warnf("Failed to apply policy. Cannot use \"kubearmor.io/container.name\" and other labels together.")
		return pb.PolicyStatus_Invalid
	} else if !ok && dm.RuntimeEnforcer != nil && dm.RuntimeEnforcer.EnforcerType == "AppArmor" {
		// this label is necessary in apparmor because profile needs to be created before container
		dm.Logger.Warnf("Received policy for AppArmor enforcer without \"kubearmor.io/container.name\"")
		return pb.PolicyStatus_Invalid
	}

	secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + secPolicy.Metadata["namespaceName"]}
	containername := ""
	for k, v := range secPolicy.Spec.Selector.MatchLabels {
		secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
		// TODO: regex based matching
		if k == "kubearmor.io/container.name" {
			expr, err := regexp.CompilePOSIX(v)
			if err != nil {
				dm.Logger.Warnf("Failed to parse expression for \"kubearmor.io/container.name\": %s", err.Error())
				return pb.PolicyStatus_Invalid
			}
			containername = expr.String()
		}
	}

	sort.Slice(secPolicy.Spec.Selector.Identities, func(i, j int) bool {
		return secPolicy.Spec.Selector.Identities[i] < secPolicy.Spec.Selector.Identities[j]
	})

	// add severities, tags, messages, and actions

	if len(secPolicy.Spec.Process.MatchPaths) > 0 {
		for idx, path := range secPolicy.Spec.Process.MatchPaths {
			if path.Severity == 0 {
				if secPolicy.Spec.Process.Severity != 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Severity = secPolicy.Spec.Process.Severity
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(path.Tags) == 0 {
				if len(secPolicy.Spec.Process.Tags) > 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Tags = secPolicy.Spec.Process.Tags
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(path.Message) == 0 {
				if len(secPolicy.Spec.Process.Message) > 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Message = secPolicy.Spec.Process.Message
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(path.Action) == 0 {
				if len(secPolicy.Spec.Process.Action) > 0 {
					secPolicy.Spec.Process.MatchPaths[idx].Action = secPolicy.Spec.Process.Action
				} else {
					secPolicy.Spec.Process.MatchPaths[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
		for idx, dir := range secPolicy.Spec.Process.MatchDirectories {
			if dir.Severity == 0 {
				if secPolicy.Spec.Process.Severity != 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Severity = secPolicy.Spec.Process.Severity
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(dir.Tags) == 0 {
				if len(secPolicy.Spec.Process.Tags) > 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Tags = secPolicy.Spec.Process.Tags
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(dir.Message) == 0 {
				if len(secPolicy.Spec.Process.Message) > 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Message = secPolicy.Spec.Process.Message
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(dir.Action) == 0 {
				if len(secPolicy.Spec.Process.Action) > 0 {
					secPolicy.Spec.Process.MatchDirectories[idx].Action = secPolicy.Spec.Process.Action
				} else {
					secPolicy.Spec.Process.MatchDirectories[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
		for idx, pat := range secPolicy.Spec.Process.MatchPatterns {
			if pat.Severity == 0 {
				if secPolicy.Spec.Process.Severity != 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Severity = secPolicy.Spec.Process.Severity
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(pat.Tags) == 0 {
				if len(secPolicy.Spec.Process.Tags) > 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Tags = secPolicy.Spec.Process.Tags
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(pat.Message) == 0 {
				if len(secPolicy.Spec.Process.Message) > 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Message = secPolicy.Spec.Process.Message
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(pat.Action) == 0 {
				if len(secPolicy.Spec.Process.Action) > 0 {
					secPolicy.Spec.Process.MatchPatterns[idx].Action = secPolicy.Spec.Process.Action
				} else {
					secPolicy.Spec.Process.MatchPatterns[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPaths) > 0 {
		for idx, path := range secPolicy.Spec.File.MatchPaths {
			if path.Severity == 0 {
				if secPolicy.Spec.File.Severity != 0 {
					secPolicy.Spec.File.MatchPaths[idx].Severity = secPolicy.Spec.File.Severity
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(path.Tags) == 0 {
				if len(secPolicy.Spec.File.Tags) > 0 {
					secPolicy.Spec.File.MatchPaths[idx].Tags = secPolicy.Spec.File.Tags
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(path.Message) == 0 {
				if len(secPolicy.Spec.File.Message) > 0 {
					secPolicy.Spec.File.MatchPaths[idx].Message = secPolicy.Spec.File.Message
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(path.Action) == 0 {
				if len(secPolicy.Spec.File.Action) > 0 {
					secPolicy.Spec.File.MatchPaths[idx].Action = secPolicy.Spec.File.Action
				} else {
					secPolicy.Spec.File.MatchPaths[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchDirectories) > 0 {
		for idx, dir := range secPolicy.Spec.File.MatchDirectories {
			if dir.Severity == 0 {
				if secPolicy.Spec.File.Severity != 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Severity = secPolicy.Spec.File.Severity
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(dir.Tags) == 0 {
				if len(secPolicy.Spec.File.Tags) > 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Tags = secPolicy.Spec.File.Tags
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(dir.Message) == 0 {
				if len(secPolicy.Spec.File.Message) > 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Message = secPolicy.Spec.File.Message
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(dir.Action) == 0 {
				if len(secPolicy.Spec.File.Action) > 0 {
					secPolicy.Spec.File.MatchDirectories[idx].Action = secPolicy.Spec.File.Action
				} else {
					secPolicy.Spec.File.MatchDirectories[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.File.MatchPatterns) > 0 {
		for idx, pat := range secPolicy.Spec.File.MatchPatterns {
			if pat.Severity == 0 {
				if secPolicy.Spec.File.Severity != 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Severity = secPolicy.Spec.File.Severity
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(pat.Tags) == 0 {
				if len(secPolicy.Spec.File.Tags) > 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Tags = secPolicy.Spec.File.Tags
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(pat.Message) == 0 {
				if len(secPolicy.Spec.File.Message) > 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Message = secPolicy.Spec.File.Message
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(pat.Action) == 0 {
				if len(secPolicy.Spec.File.Action) > 0 {
					secPolicy.Spec.File.MatchPatterns[idx].Action = secPolicy.Spec.File.Action
				} else {
					secPolicy.Spec.File.MatchPatterns[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Network.MatchProtocols) > 0 {
		for idx, proto := range secPolicy.Spec.Network.MatchProtocols {
			if proto.Severity == 0 {
				if secPolicy.Spec.Network.Severity != 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Severity = secPolicy.Spec.Network.Severity
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(proto.Tags) == 0 {
				if len(secPolicy.Spec.Network.Tags) > 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Tags = secPolicy.Spec.Network.Tags
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(proto.Message) == 0 {
				if len(secPolicy.Spec.Network.Message) > 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Message = secPolicy.Spec.Network.Message
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(proto.Action) == 0 {
				if len(secPolicy.Spec.Network.Action) > 0 {
					secPolicy.Spec.Network.MatchProtocols[idx].Action = secPolicy.Spec.Network.Action
				} else {
					secPolicy.Spec.Network.MatchProtocols[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	if len(secPolicy.Spec.Capabilities.MatchCapabilities) > 0 {
		for idx, cap := range secPolicy.Spec.Capabilities.MatchCapabilities {
			if cap.Severity == 0 {
				if secPolicy.Spec.Capabilities.Severity != 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Severity = secPolicy.Spec.Capabilities.Severity
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(cap.Tags) == 0 {
				if len(secPolicy.Spec.Capabilities.Tags) > 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Tags = secPolicy.Spec.Capabilities.Tags
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(cap.Message) == 0 {
				if len(secPolicy.Spec.Capabilities.Message) > 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Message = secPolicy.Spec.Capabilities.Message
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(cap.Action) == 0 {
				if len(secPolicy.Spec.Capabilities.Action) > 0 {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Action = secPolicy.Spec.Capabilities.Action
				} else {
					secPolicy.Spec.Capabilities.MatchCapabilities[idx].Action = secPolicy.Spec.Action
				}
			}
		}
	}

	// handle updates to global policy store
	if event.Type == "ADDED" {
		dm.SecurityPoliciesLock.Lock()
		newPolicy := true
		for idx, policy := range dm.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				// update
				newPolicy = false
				dm.SecurityPolicies[idx] = secPolicy
				break
			}
		}
		if newPolicy {
			dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
		}
		dm.SecurityPoliciesLock.Unlock()
	} else if event.Type == "DELETED" {
		dm.SecurityPoliciesLock.Lock()
		for idx, policy := range dm.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
				break
			}
		}
		dm.SecurityPoliciesLock.Unlock()
	}

	dm.Logger.Printf("Detected a Container Security Policy (%s/%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

	createEndPoint := true
	endPointIndex := -1
	newPoint := tp.EndPoint{}
	policyStatus := pb.PolicyStatus_Applied

	// consider reducing coverage for this lock
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()
	for idx, endPoint := range dm.EndPoints {
		endPointIndex++

		// update container rules if there exists another endpoint with same policy.Metadata["policyName"]
		// this is for handling cases when an existing policy has been sent with modified identites - we delete security policies
		// from previously matched endpoint
		for policyIndex, policy := range endPoint.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] && !kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) {
				// if no containers and only policy with this name exists, delete endpoint
				if len(endPoint.Containers) == 0 && len(endPoint.SecurityPolicies) == 1 {
					dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)

					// delete unnecessary security policies
					dm.Logger.UpdateSecurityPolicies("DELETED", endPoint)
					endPoint.SecurityPolicies = append(endPoint.SecurityPolicies[:0], endPoint.SecurityPolicies[1:]...)
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
					if dm.Presets != nil {
						dm.Presets.UpdateSecurityPolicies(endPoint)
					}
					endPoint = tp.EndPoint{}
					endPointIndex--
				} else if len(endPoint.SecurityPolicies) >= 1 {
					// else update the security policies for this endpoint
					// as it has multiple containers/policies

					dm.EndPoints[idx].SecurityPolicies = append(
						dm.EndPoints[idx].SecurityPolicies[:policyIndex],
						dm.EndPoints[idx].SecurityPolicies[policyIndex+1:]...,
					)
					endPoint = dm.EndPoints[idx]

					if cfg.GlobalCfg.Policy {
						// update security policies
						dm.Logger.UpdateSecurityPolicies("MODIFIED", endPoint)

						if endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
							if dm.RuntimeEnforcer != nil {
								// enforce security policies
								dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
							}
							if dm.Presets != nil {
								// enforce preset rules
								dm.Presets.UpdateSecurityPolicies(endPoint)
							}
						}
					}
				}
				break
			}
		}

		// update policy for all endpoints that match
		if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) {
			// endpoint exists for this sec policy, so we update it
			createEndPoint = false
			newPoint = endPoint

			endPointIndex, policyStatus = dm.handlePolicyEvent(event.Type, createEndPoint, secPolicy, newPoint, endPointIndex, containername)

			switch policyStatus {
			case pb.PolicyStatus_Applied, pb.PolicyStatus_Deleted, pb.PolicyStatus_Modified:
				continue
			default:
				return policyStatus
			}
		}
	}

	// endpoint doesn't exist for this policy yet
	if createEndPoint {
		_, policyStatus = dm.handlePolicyEvent(event.Type, true, secPolicy, newPoint, endPointIndex, containername)
		switch policyStatus {
		case pb.PolicyStatus_Applied, pb.PolicyStatus_Deleted, pb.PolicyStatus_Modified:
		default:
			return policyStatus
		}
	}

	// backup/remove container policies
	if !dm.K8sEnabled && (cfg.GlobalCfg.KVMAgent || cfg.GlobalCfg.Policy) {
		if event.Type == "ADDED" || event.Type == "MODIFIED" {
			// backup SecurityPolicy to file
			dm.backupKubeArmorContainerPolicy(secPolicy)
		} else if event.Type == "DELETED" {
			dm.removeBackUpPolicy(secPolicy.Metadata["policyName"])
		}
	}
	if event.Type == "ADDED" {
		return pb.PolicyStatus_Applied
	} else if event.Type == "DELETED" {
		return pb.PolicyStatus_Deleted
	}

	return pb.PolicyStatus_Modified
}

// ================================= //
// == HostPolicy Backup & Restore == //
// ================================= //

// backupKubeArmorHostPolicy Function
func (dm *KubeArmorDaemon) backupKubeArmorHostPolicy(policy tp.HostSecurityPolicy) {
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(cfg.PolicyDir); err != nil {
		if err = os.MkdirAll(cfg.PolicyDir, 0700); err != nil {
			kg.Warnf("Dir creation failed for [%v]", cfg.PolicyDir)
			return
		}
	}

	var file *os.File
	var err error

	if file, err = os.Create(cfg.PolicyDir + policy.Metadata["policyName"] + ".yaml"); err == nil {
		if policyBytes, err := json.Marshal(policy); err == nil {
			if _, err = file.Write(policyBytes); err == nil {
				if err := file.Close(); err != nil {
					dm.Logger.Err(err.Error())
				}
			}
		}
	}
}

// Back up KubeArmor container policies in /opt/kubearmor/policies
func (dm *KubeArmorDaemon) backupKubeArmorContainerPolicy(policy tp.SecurityPolicy) {
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(cfg.PolicyDir); err != nil {
		if err = os.MkdirAll(cfg.PolicyDir, 0700); err != nil {
			kg.Warnf("Dir creation failed for [%v]", cfg.PolicyDir)
			return
		}
	}

	var file *os.File
	var err error

	if file, err = os.Create(cfg.PolicyDir + policy.Metadata["policyName"] + ".yaml"); err == nil {
		if policyBytes, err := json.Marshal(policy); err == nil {
			if _, err = file.Write(policyBytes); err == nil {
				if err := file.Close(); err != nil {
					dm.Logger.Err(err.Error())
				}
			}
		}
	}
}

func (dm *KubeArmorDaemon) restoreKubeArmorPolicies() {
	if _, err := os.Stat(cfg.PolicyDir); err != nil {
		kg.Warn("Policies dir not found for restoration")
		return
	}

	// List all policies files from "/opt/kubearmor/policies" path
	if policyFiles, err := os.ReadDir(cfg.PolicyDir); err == nil {
		for _, file := range policyFiles {
			if data, err := os.ReadFile(cfg.PolicyDir + file.Name()); err == nil {

				var k struct {
					Metadata map[string]string `json:"metadata"`
				}

				err := json.Unmarshal(data, &k)
				if err != nil {
					kg.Errf("Failed to unmarshal policy: %v", err)
					continue
				}

				if _, ok := k.Metadata["namespaceName"]; ok { // ContainerPolicy contains namespaceName
					var containerPolicy tp.K8sKubeArmorPolicy
					if err := json.Unmarshal(data, &containerPolicy); err == nil {
						containerPolicy.Metadata.Name = k.Metadata["policyName"]
						dm.ParseAndUpdateContainerSecurityPolicy(tp.K8sKubeArmorPolicyEvent{
							Type:   "ADDED",
							Object: containerPolicy,
						})
					}

				} else { // HostSecurityPolicy
					var hostPolicy tp.K8sKubeArmorHostPolicy
					if err := json.Unmarshal(data, &hostPolicy); err == nil {
						hostPolicy.Metadata.Name = k.Metadata["policyName"]
						dm.ParseAndUpdateHostSecurityPolicy(tp.K8sKubeArmorHostPolicyEvent{
							Type:   "ADDED",
							Object: hostPolicy,
						})
					} else {
						kg.Errf("Failed to unmarshal host policy: %v", err)
					}
				}
			}
		}

		if len(policyFiles) == 0 {
			kg.Warn("No policies found for restoration")
		}
	}
}

// removeBackUpPolicy Function
func (dm *KubeArmorDaemon) removeBackUpPolicy(name string) {

	fname := cfg.PolicyDir + name + ".yaml"
	// Check for "/opt/kubearmor/policies" path. If dir not found, create the same
	if _, err := os.Stat(fname); err != nil {
		kg.Printf("Backup policy [%v] not exist", fname)
		return
	}

	if err := os.Remove(fname); err != nil {
		kg.Errf("unable to delete file:%s err=%s", fname, err.Error())
	}
}
