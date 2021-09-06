// Copyright 2021 Authors of KubeArmor
// SPDX-License-Identifier: Apache-2.0

package core

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"sort"
	"strings"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================ //
// == Pod Update == //
// ================ //

// UpdateContainerGroupWithPod Function
func (dm *KubeArmorDaemon) UpdateContainerGroupWithPod(action string, pod tp.K8sPod) {
	dm.ContainerGroupsLock.Lock()
	defer dm.ContainerGroupsLock.Unlock()

	if action == "ADDED" {
		// create a new container group

		newGroup := tp.ContainerGroup{}

		newGroup.NamespaceName = pod.Metadata["namespaceName"]
		newGroup.ContainerGroupName = pod.Metadata["podName"]

		newGroup.Labels = []string{}
		newGroup.Identities = []string{}
		newGroup.Containers = []string{}
		newGroup.AppArmorProfiles = map[string]string{}

		newGroup.Identities = append(newGroup.Identities, "namespaceName="+newGroup.NamespaceName)

		// update labels and identities
		for k, v := range pod.Labels {
			if !kl.ContainsElement(newGroup.Labels, k+"="+v) {
				newGroup.Labels = append(newGroup.Labels, k+"="+v)
			}

			if !kl.ContainsElement(newGroup.Identities, k+"="+v) {
				newGroup.Identities = append(newGroup.Identities, k+"="+v)
			}
		}

		sort.Slice(newGroup.Identities, func(i, j int) bool {
			return newGroup.Identities[i] < newGroup.Identities[j]
		})

		// update container list
		for k := range pod.Containers {
			if !kl.ContainsElement(newGroup.Containers, k) {
				newGroup.Containers = append(newGroup.Containers, k)
			}
		}

		// update flags
		if pod.Annotations["kubearmor-policy"] == "enabled" {
			newGroup.PolicyEnabled = tp.KubeArmorPolicyEnabled
		} else {
			newGroup.PolicyEnabled = tp.KubeArmorPolicyDisabled
		}

		// parse annotations and set flags
		for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
			if visibility == "process" {
				newGroup.ProcessVisibilityEnabled = true
			} else if visibility == "file" {
				newGroup.FileVisibilityEnabled = true
			} else if visibility == "network" {
				newGroup.NetworkVisibilityEnabled = true
			} else if visibility == "capabilities" {
				newGroup.CapabilitiesVisibilityEnabled = true
			}
		}

		// update containers
		dm.ContainersLock.Lock()
		for _, containerID := range newGroup.Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = newGroup.NamespaceName
			container.ContainerGroupName = newGroup.ContainerGroupName
			container.ContainerName = pod.Containers[containerID]

			container.PolicyEnabled = newGroup.PolicyEnabled

			container.ProcessVisibilityEnabled = newGroup.ProcessVisibilityEnabled
			container.FileVisibilityEnabled = newGroup.FileVisibilityEnabled
			container.NetworkVisibilityEnabled = newGroup.NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = newGroup.CapabilitiesVisibilityEnabled

			newGroup.AppArmorProfiles[containerID] = container.AppArmorProfile

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		// update security policies with the identities
		newGroup.SecurityPolicies = dm.GetSecurityPolicies(newGroup.Identities)

		// add the container group into the container group list
		dm.ContainerGroups = append(dm.ContainerGroups, newGroup)

		if newGroup.PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// create and register security profiles
			dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod, true)
		}

		// update security policies
		dm.LogFeeder.UpdateSecurityPolicies(action, newGroup)

		// enforce security policies
		dm.RuntimeEnforcer.UpdateSecurityPolicies(newGroup)

	} else if action == "MODIFIED" {
		for idx, conGroup := range dm.ContainerGroups {
			if pod.Metadata["namespaceName"] == conGroup.NamespaceName && pod.Metadata["podName"] == conGroup.ContainerGroupName {
				// update the labels and identities of the container group

				dm.ContainerGroups[idx].Labels = []string{}
				dm.ContainerGroups[idx].Identities = []string{}
				dm.ContainerGroups[idx].Containers = []string{}
				dm.ContainerGroups[idx].AppArmorProfiles = map[string]string{}

				dm.ContainerGroups[idx].Identities = append(dm.ContainerGroups[idx].Identities, "namespaceName="+dm.ContainerGroups[idx].NamespaceName)

				for k, v := range pod.Labels {
					if !kl.ContainsElement(dm.ContainerGroups[idx].Labels, k+"="+v) {
						dm.ContainerGroups[idx].Labels = append(dm.ContainerGroups[idx].Labels, k+"="+v)
					}

					if !kl.ContainsElement(dm.ContainerGroups[idx].Identities, k+"="+v) {
						dm.ContainerGroups[idx].Identities = append(dm.ContainerGroups[idx].Identities, k+"="+v)
					}
				}

				sort.Slice(dm.ContainerGroups[idx].Identities, func(i, j int) bool {
					return dm.ContainerGroups[idx].Identities[i] < dm.ContainerGroups[idx].Identities[j]
				})

				// update container list
				for k := range pod.Containers {
					if !kl.ContainsElement(dm.ContainerGroups[idx].Containers, k) {
						dm.ContainerGroups[idx].Containers = append(dm.ContainerGroups[idx].Containers, k)
					}
				}

				// update flags

				prevPolicyEnabled := dm.ContainerGroups[idx].PolicyEnabled

				if pod.Annotations["kubearmor-policy"] == "enabled" {
					dm.ContainerGroups[idx].PolicyEnabled = tp.KubeArmorPolicyEnabled
				} else {
					dm.ContainerGroups[idx].PolicyEnabled = tp.KubeArmorPolicyDisabled
				}

				// parse annotations and set flags

				dm.ContainerGroups[idx].ProcessVisibilityEnabled = false
				dm.ContainerGroups[idx].FileVisibilityEnabled = false
				dm.ContainerGroups[idx].NetworkVisibilityEnabled = false
				dm.ContainerGroups[idx].CapabilitiesVisibilityEnabled = false

				for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
					if visibility == "process" {
						dm.ContainerGroups[idx].ProcessVisibilityEnabled = true
					} else if visibility == "file" {
						dm.ContainerGroups[idx].FileVisibilityEnabled = true
					} else if visibility == "network" {
						dm.ContainerGroups[idx].NetworkVisibilityEnabled = true
					} else if visibility == "capabilities" {
						dm.ContainerGroups[idx].CapabilitiesVisibilityEnabled = true
					}
				}

				// update containers
				dm.ContainersLock.Lock()
				for _, containerID := range dm.ContainerGroups[idx].Containers {
					container := dm.Containers[containerID]

					container.NamespaceName = dm.ContainerGroups[idx].NamespaceName
					container.ContainerGroupName = dm.ContainerGroups[idx].ContainerGroupName
					container.ContainerName = pod.Containers[containerID]

					container.PolicyEnabled = dm.ContainerGroups[idx].PolicyEnabled

					container.ProcessVisibilityEnabled = dm.ContainerGroups[idx].ProcessVisibilityEnabled
					container.FileVisibilityEnabled = dm.ContainerGroups[idx].FileVisibilityEnabled
					container.NetworkVisibilityEnabled = dm.ContainerGroups[idx].NetworkVisibilityEnabled
					container.CapabilitiesVisibilityEnabled = dm.ContainerGroups[idx].CapabilitiesVisibilityEnabled

					dm.ContainerGroups[idx].AppArmorProfiles[containerID] = container.AppArmorProfile

					dm.Containers[containerID] = container
				}
				dm.ContainersLock.Unlock()

				if prevPolicyEnabled != tp.KubeArmorPolicyEnabled && dm.ContainerGroups[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// initialize and register security profiles
					dm.RuntimeEnforcer.UpdateSecurityProfiles("ADDED", pod, true)
				}

				// get security policies according to the updated identities
				dm.ContainerGroups[idx].SecurityPolicies = dm.GetSecurityPolicies(dm.ContainerGroups[idx].Identities)

				// update security policies
				dm.LogFeeder.UpdateSecurityPolicies(action, dm.ContainerGroups[idx])

				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[idx])

				break
			}
		}

	} else { // DELETED
		for idx, conGroup := range dm.ContainerGroups {
			if pod.Metadata["namespaceName"] == conGroup.NamespaceName && pod.Metadata["podName"] == conGroup.ContainerGroupName {
				if dm.ContainerGroups[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// initialize and unregister security profiles
					dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod, true)
				}

				// remove container group
				dm.ContainerGroups = append(dm.ContainerGroups[:idx], dm.ContainerGroups[idx+1:]...)

				break
			}
		}
	}
}

// WatchK8sPods Function
func (dm *KubeArmorDaemon) WatchK8sPods() {
	for {
		if resp := K8s.WatchK8sPods(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sPodEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				// create a pod

				pod := tp.K8sPod{}

				pod.Metadata = map[string]string{}
				pod.Metadata["namespaceName"] = event.Object.ObjectMeta.Namespace
				pod.Metadata["podName"] = event.Object.ObjectMeta.Name

				if len(event.Object.ObjectMeta.OwnerReferences) > 0 {
					if event.Object.ObjectMeta.OwnerReferences[0].Kind == "ReplicaSet" {
						deploymentName := K8s.GetDeploymentNameControllingReplicaSet(pod.Metadata["namespaceName"], event.Object.ObjectMeta.OwnerReferences[0].Name)
						if deploymentName != "" {
							pod.Metadata["deploymentName"] = deploymentName
						}
					}
				}

				pod.Annotations = map[string]string{}
				for k, v := range event.Object.Annotations {
					pod.Annotations[k] = v
				}

				pod.Labels = map[string]string{}
				for k, v := range event.Object.Labels {
					if k == "pod-template-hash" {
						continue
					}

					if k == "pod-template-generation" {
						continue
					}

					if k == "controller-revision-hash" {
						continue
					}
					pod.Labels[k] = v
				}

				pod.Containers = map[string]string{}
				for _, container := range event.Object.Status.ContainerStatuses {
					if len(container.ContainerID) > 0 {
						if strings.HasPrefix(container.ContainerID, "docker://") {
							containerID := strings.TrimPrefix(container.ContainerID, "docker://")
							pod.Containers[containerID] = container.Name
						} else if strings.HasPrefix(container.ContainerID, "containerd://") {
							containerID := strings.TrimPrefix(container.ContainerID, "containerd://")
							pod.Containers[containerID] = container.Name
						}
					}
				}

				// == //

				if pod.Metadata["namespaceName"] == "kube-system" {
					// exception: kubernetes app
					if _, ok := pod.Labels["k8s-app"]; ok {
						pod.Annotations["kubearmor-policy"] = "audited"
					}

					// exception: cilium-operator
					if val, ok := pod.Labels["io.cilium/app"]; ok && val == "operator" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				}

				// == //

				if dm.EnableEnforcerPerPod {
					if _, ok := pod.Annotations["kubearmor-policy"]; ok {
						if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" {
							pod.Annotations["kubearmor-policy"] = "disabled"
						}
					} else {
						pod.Annotations["kubearmor-policy"] = "disabled"
					}
				} else { // EnableEnforcerAll
					if _, ok := pod.Annotations["kubearmor-policy"]; ok {
						if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" {
							pod.Annotations["kubearmor-policy"] = "enabled"
						}
					} else {
						pod.Annotations["kubearmor-policy"] = "enabled"
					}
				}

				// == //

				if dm.RuntimeEnforcer.IsEnabled() {
					if lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm"); err == nil {
						// exception: no AppArmor
						if !strings.Contains(string(lsm), "apparmor") {
							if pod.Annotations["kubearmor-policy"] == "enabled" {
								pod.Annotations["kubearmor-policy"] = "disabled"
							}
						}
					}
				} else { // No LSM
					if pod.Annotations["kubearmor-policy"] == "enabled" {
						pod.Annotations["kubearmor-policy"] = "disabled"
					}
				}

				if _, ok := pod.Annotations["kubearmor-visibility"]; !ok {
					pod.Annotations["kubearmor-visibility"] = "none"
				}

				if event.Type == "ADDED" || event.Type == "MODIFIED" {
					exist := false

					dm.K8sPodsLock.Lock()
					for _, k8spod := range dm.K8sPods {
						if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
							if k8spod.Annotations["kubearmor-policy"] == "patched" {
								exist = true
								break
							}
						}
					}
					dm.K8sPodsLock.Unlock()

					if exist {
						continue
					}
				}

				// == AppArmor == //

				if pod.Annotations["kubearmor-policy"] == "enabled" {
					appArmorAnnotations := map[string]string{}
					updateAppArmor := false

					for k, v := range pod.Annotations {
						if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io") {
							if v == "unconfined" {
								containerName := strings.Split(k, "/")[1]
								appArmorAnnotations[containerName] = v
							} else {
								containerName := strings.Split(k, "/")[1]
								appArmorAnnotations[containerName] = strings.Split(v, "/")[1]
							}
						}
					}

					for _, container := range event.Object.Spec.Containers {
						if _, ok := appArmorAnnotations[container.Name]; !ok {
							appArmorAnnotations[container.Name] = "kubearmor-" + pod.Metadata["namespaceName"] + "-" + container.Name
							updateAppArmor = true
						}
					}

					if dm.RuntimeEnforcer.GetEnforcerType() == "apparmor" {
						if updateAppArmor && (event.Type == "ADDED" || event.Type == "MODIFIED") {
							if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
								if err := K8s.PatchDeploymentWithAppArmorAnnotations(pod.Metadata["namespaceName"], deploymentName, appArmorAnnotations); err != nil {
									dm.LogFeeder.Errf("Failed to update AppArmor Profiles (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
								} else {
									dm.LogFeeder.Printf("Patched AppArmor Profiles (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
								}
								pod.Annotations["kubearmor-policy"] = "patched"
							}
						}
					}
				}

				// == //

				// update the pod into the pod list

				dm.K8sPodsLock.Lock()

				if event.Type == "ADDED" {
					if !kl.ContainsElement(dm.K8sPods, pod) {
						dm.K8sPods = append(dm.K8sPods, pod)
					}
				} else if event.Type == "MODIFIED" {
					for idx, k8spod := range dm.K8sPods {
						if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
							dm.K8sPods[idx] = pod
							break
						}
					}
				} else if event.Type == "DELETED" {
					for idx, k8spod := range dm.K8sPods {
						if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
							dm.K8sPods = append(dm.K8sPods[:idx], dm.K8sPods[idx+1:]...)
							break
						}
					}
				} else { // Otherwise
					dm.K8sPodsLock.Unlock()
					continue
				}

				dm.K8sPodsLock.Unlock()

				if pod.Annotations["kubearmor-policy"] != "patched" {
					dm.LogFeeder.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event.Type), pod.Metadata["namespaceName"], pod.Metadata["podName"])

					// update a container group corresponding to the pod
					dm.UpdateContainerGroupWithPod(event.Type, pod)
				}
			}
		} else {
			time.Sleep(time.Second * 1)
		}
	}
}

// ============================ //
// == Security Policy Update == //
// ============================ //

// GetSecurityPolicies Function
func (dm *KubeArmorDaemon) GetSecurityPolicies(identities []string) []tp.SecurityPolicy {
	dm.SecurityPoliciesLock.Lock()
	defer dm.SecurityPoliciesLock.Unlock()

	secPolicies := []tp.SecurityPolicy{}

	for _, policy := range dm.SecurityPolicies {
		if kl.MatchIdentities(policy.Spec.Selector.Identities, identities) {
			secPolicy := tp.SecurityPolicy{}
			if err := kl.Clone(policy, &secPolicy); err != nil {
				fmt.Println("Failed to clone a policy")
			}
			secPolicies = append(secPolicies, secPolicy)
		}
	}

	return secPolicies
}

// UpdateSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateSecurityPolicy(action string, secPolicy tp.SecurityPolicy) {
	dm.ContainerGroupsLock.Lock()
	defer dm.ContainerGroupsLock.Unlock()

	for idx, conGroup := range dm.ContainerGroups {
		// update a security policy
		if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, conGroup.Identities) {
			if action == "ADDED" {
				// add a new security policy if it doesn't exist
				if !kl.ContainsElement(conGroup.SecurityPolicies, secPolicy) {
					dm.ContainerGroups[idx].SecurityPolicies = append(dm.ContainerGroups[idx].SecurityPolicies, secPolicy)
				}
			} else if action == "MODIFIED" {
				for idxP, policy := range conGroup.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						dm.ContainerGroups[idx].SecurityPolicies[idxP] = secPolicy
						break
					}
				}
			} else if action == "DELETED" {
				// remove the given policy from the security policy list of this container group
				for idxP, policy := range conGroup.SecurityPolicies {
					if reflect.DeepEqual(secPolicy, policy) {
						dm.ContainerGroups[idx].SecurityPolicies = append(dm.ContainerGroups[idx].SecurityPolicies[:idxP], dm.ContainerGroups[idx].SecurityPolicies[idxP+1:]...)
						break
					}
				}
			}

			// update security policies
			dm.LogFeeder.UpdateSecurityPolicies("UPDATED", dm.ContainerGroups[idx])

			// enforce security policies
			dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[idx])
		}
	}
}

// WatchSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchSecurityPolicies() {
	for {
		if !K8s.CheckCustomResourceDefinition("kubearmorpolicies") {
			time.Sleep(time.Second * 1)
			continue
		}

		if resp := K8s.WatchK8sSecurityPolicies(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sKubeArmorPolicyEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Object.Status.PolicyStatus != "" && event.Object.Status.PolicyStatus != "OK" {
					continue
				}

				dm.SecurityPoliciesLock.Lock()

				// create a security policy

				secPolicy := tp.SecurityPolicy{}

				secPolicy.Metadata = map[string]string{}
				secPolicy.Metadata["namespaceName"] = event.Object.Metadata.Namespace
				secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

				if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
					fmt.Println("Failed to clone a spec")
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

				secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, "namespaceName="+event.Object.Metadata.Namespace)

				for k, v := range secPolicy.Spec.Selector.MatchLabels {
					if !kl.ContainsElement(secPolicy.Spec.Selector.Identities, k+"="+v) {
						secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
					}
				}

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

				// update a security policy into the policy list

				if event.Type == "ADDED" {
					if !kl.ContainsElement(dm.SecurityPolicies, secPolicy) {
						dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
					}
				} else if event.Type == "MODIFIED" {
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies[idx] = secPolicy
							break
						}
					}
				} else if event.Type == "DELETED" {
					for idx, policy := range dm.SecurityPolicies {
						if reflect.DeepEqual(secPolicy, policy) {
							dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
							break
						}
					}
				}

				dm.SecurityPoliciesLock.Unlock()

				dm.LogFeeder.Printf("Detected a Security Policy (%s/%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

				// apply security policies to containers
				dm.UpdateSecurityPolicy(event.Type, secPolicy)
			}
		}
	}
}
