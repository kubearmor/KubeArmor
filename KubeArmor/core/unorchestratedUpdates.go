// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package core

import (
	"encoding/json"
	"os"
	"sort"
	"strings"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
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

	dm.UpdateVisibility("ADDED", "container_namespace", visibility)
}

// ====================================== //
// == Container Security Policy Update == //
// ====================================== //

// MatchandUpdateContainerSecurityPolicies finds relevant endpoint for containers and updates the security policies for enforcement
func (dm *KubeArmorDaemon) MatchandUpdateContainerSecurityPolicies(cid string) {
	for idx, ep := range dm.EndPoints {
		if ep.EndPointName == dm.Containers[cid].ContainerName {
			ep.Containers = append(ep.Containers, cid)
			dm.EndPoints[idx] = ep
			ctr := dm.Containers[cid]
			ctr.NamespaceName = ep.NamespaceName
			ctr.EndPointName = ep.EndPointName
			dm.Containers[cid] = ctr
			if cfg.GlobalCfg.Policy {
				// update security policies
				dm.Logger.UpdateSecurityPolicies("MODIFIED", ep)
				if dm.RuntimeEnforcer != nil && ep.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(ep)
				}
			}
		}
	}
}

// MatchandRemoveContainerSecurityPolicies finds relevant endpoint for containers and removes cid from the container list
func (dm *KubeArmorDaemon) MatchandRemoveContainerFromEndpoint(cid string) {
	for idx, ep := range dm.EndPoints {
		if ep.EndPointName != dm.Containers[cid].ContainerName {
			continue
		}
		for i, c := range ep.Containers {
			if c != cid {
				continue
			}
			ep.Containers = append(ep.Containers[:i], ep.Containers[i+1:]...)
			break
		}
		dm.EndPoints[idx] = ep
	}
}

// ParseAndUpdateContainerSecurityPolicy Function
func (dm *KubeArmorDaemon) ParseAndUpdateContainerSecurityPolicy(event tp.K8sKubeArmorPolicyEvent) {
	// create a container security policy
	secPolicy := tp.SecurityPolicy{}

	secPolicy.Metadata = map[string]string{}
	secPolicy.Metadata["namespaceName"] = "container_namespace" //event.Object.Metadata.Namespace
	secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

	if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
		dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
		return
	}

	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Network.MatchProtocols)
	kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Capabilities.MatchCapabilities)

	if secPolicy.Spec.Severity == 0 {
		secPolicy.Spec.Severity = 1 // the lowest severity, by default
	}

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

	secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + event.Object.Metadata.Namespace}
	containername := ""
	for k, v := range secPolicy.Spec.Selector.MatchLabels {
		secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
		if k == "kubearmor.io/container.name" {
			containername = v
		} else {
			dm.Logger.Warnf("Fail to apply policy. The MatchLabels container name key should be `kubearmor.io/container.name` ")
			return
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

	dm.Logger.Printf("Detected a Container Security Policy (%s/%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

	appArmorAnnotations := map[string]string{}
	appArmorAnnotations[containername] = "kubearmor_" + containername

	newPoint := tp.EndPoint{}

	i := -1

	for idx, endPoint := range dm.EndPoints {
		if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) {
			i = idx
			newPoint = endPoint
			break
		}
	}

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
	if policymatch == 0 && event.Type == "DELETED" {
		dm.Logger.Warnf("Failed to delete security policy. Policy doesn't exist")
		return
	}

	for idx, policy := range newPoint.SecurityPolicies {
		if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
			if event.Type == "DELETED" {
				newPoint.SecurityPolicies = append(newPoint.SecurityPolicies[:idx], newPoint.SecurityPolicies[idx+1:]...)
				break
			} else {
				event.Type = "MODIFIED"
				// Policy already exists so modify
				newPoint.SecurityPolicies[idx] = secPolicy
			}
		}
	}

	if event.Type == "ADDED" {
		dm.RuntimeEnforcer.UpdateAppArmorProfiles(containername, "ADDED", appArmorAnnotations)

		newPoint.SecurityPolicies = append(newPoint.SecurityPolicies, secPolicy)
		if i < 0 {
			// Create new EndPoint
			newPoint.NamespaceName = secPolicy.Metadata["namespaceName"]
			newPoint.EndPointName = containername
			newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
			newPoint.Identities = secPolicy.Spec.Selector.Identities

			newPoint.ProcessVisibilityEnabled = true
			newPoint.FileVisibilityEnabled = true
			newPoint.NetworkVisibilityEnabled = true
			newPoint.CapabilitiesVisibilityEnabled = true
			newPoint.Containers = []string{}
			dm.ContainersLock.Lock()
			for idx, ctr := range dm.Containers {
				if ctr.ContainerName == containername {
					newPoint.Containers = append(newPoint.Containers, ctr.ContainerID)
					ctr.NamespaceName = newPoint.NamespaceName
					ctr.EndPointName = newPoint.EndPointName
					dm.Containers[idx] = ctr
				}
			}
			dm.ContainersLock.Unlock()

			newPoint.AppArmorProfiles = []string{"kubearmor_" + containername}

			// add the endpoint into the endpoint list
			dm.EndPoints = append(dm.EndPoints, newPoint)
		} else {
			dm.EndPoints[i] = newPoint
		}

		if cfg.GlobalCfg.Policy {
			// update security policies
			dm.Logger.UpdateSecurityPolicies("ADDED", newPoint)

			if dm.RuntimeEnforcer != nil && newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
			}
		}
	} else if event.Type == "MODIFIED" {
		dm.EndPoints[i] = newPoint
		if cfg.GlobalCfg.Policy {
			// update security policies
			dm.Logger.UpdateSecurityPolicies("MODIFIED", newPoint)

			if dm.RuntimeEnforcer != nil && newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
			}
		}
	} else { // DELETED
		// update security policies after policy deletion
		dm.Logger.UpdateSecurityPolicies("DELETED", newPoint)

		dm.EndPoints[i] = newPoint
		dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
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
					dm.Logger.Errf(err.Error())
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
					dm.Logger.Errf(err.Error())
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
					var hostPolicy tp.HostSecurityPolicy
					if err := json.Unmarshal(data, &hostPolicy); err == nil {
						dm.HostSecurityPolicies = append(dm.HostSecurityPolicies, hostPolicy)
					} else {
						kg.Errf("Failed to unmarshal host policy: %v", err)
					}
				}
			}
		}

		if len(policyFiles) != 0 {
			if len(dm.HostSecurityPolicies) != 0 {
				dm.UpdateHostSecurityPolicies()
			}
		} else {
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
