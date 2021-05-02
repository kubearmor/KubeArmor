package core

import (
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ============================ //
// == Container Group Update == //
// ============================ //

// UpdateContainerGroupWithContainer Function
func (dm *KubeArmorDaemon) UpdateContainerGroupWithContainer(action string, container tp.Container) bool {
	dm.ContainerGroupsLock.Lock()
	defer dm.ContainerGroupsLock.Unlock()

	// find the corresponding container group

	conGroupIdx := -1

	for idx, conGroup := range dm.ContainerGroups {
		if container.NamespaceName == conGroup.NamespaceName && container.ContainerGroupName == conGroup.ContainerGroupName {
			conGroupIdx = idx
			break
		}
	}

	if conGroupIdx == -1 {
		return false
	}

	// update container in a container group

	if action == "ADDED" {
		if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Identities, "containerName="+container.ContainerName) {
			dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, "containerName="+container.ContainerName)
		}

		if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Containers, container.ContainerID) {
			dm.ContainerGroups[conGroupIdx].Containers = append(dm.ContainerGroups[conGroupIdx].Containers, container.ContainerID)
			dm.ContainerGroups[conGroupIdx].AppArmorProfiles[container.ContainerID] = container.AppArmorProfile
		}
	} else { // DELETED
		if kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Identities, "containerName="+container.ContainerName) {
			for idxL, identity := range dm.ContainerGroups[conGroupIdx].Identities {
				if identity == "containerName="+container.ContainerName {
					dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities[:idxL], dm.ContainerGroups[conGroupIdx].Identities[idxL+1:]...)
					break
				}
			}
		}

		if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Containers, container.ContainerID) {
			for idxC, containerID := range dm.ContainerGroups[conGroupIdx].Containers {
				if containerID == container.ContainerID {
					dm.ContainerGroups[conGroupIdx].Containers = append(dm.ContainerGroups[conGroupIdx].Containers[:idxC], dm.ContainerGroups[conGroupIdx].Containers[idxC+1:]...)
					break
				}
			}
			delete(dm.ContainerGroups[conGroupIdx].AppArmorProfiles, container.ContainerID)
		}

		// update NsMap
		dm.SystemMonitor.DeleteContainerIDFromNsMap(container.ContainerID)
	}

	// enforce security policies
	dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[conGroupIdx])

	return true
}

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

		newGroup.Identities = append(newGroup.Identities, "namespaceName="+newGroup.NamespaceName)
		newGroup.Identities = append(newGroup.Identities, "containerGroupName="+newGroup.ContainerGroupName)

		for k, v := range pod.Labels {
			if !kl.ContainsElement(newGroup.Labels, k+"="+v) {
				newGroup.Labels = append(newGroup.Labels, k+"="+v)
			}

			if kl.ContainsElement([]string{"controller-revision-hash", "pod-template-hash", "pod-template-generation"}, k) {
				continue
			}

			if !kl.ContainsElement(newGroup.Identities, k+"="+v) {
				newGroup.Identities = append(newGroup.Identities, k+"="+v)
			}
		}

		newGroup.Containers = []string{}
		newGroup.AppArmorProfiles = map[string]string{}

		// update security policies with the identities
		newGroup.SecurityPolicies = dm.GetSecurityPolicies(newGroup.Identities)

		// update selinux profile names to the container group
		newGroup.SELinuxProfiles = map[string]string{}
		for k, v := range pod.Metadata {
			if strings.HasPrefix(k, "selinux-") {
				contName := strings.Split(k, "selinux-")[1]
				newGroup.SELinuxProfiles[contName] = v
			}
		}

		// update host-side volume mounted
		newGroup.HostVolumes = []tp.HostMountedVolume{}
		newGroup.HostVolumes = append(newGroup.HostVolumes, pod.HostVolumes...)

		// add the container group into the container group list
		dm.ContainerGroups = append(dm.ContainerGroups, newGroup)

		// update security profiles
		dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod)

	} else if action == "MODIFIED" {
		// find the corresponding container group

		conGroupIdx := -1

		for idx, conGroup := range dm.ContainerGroups {
			if pod.Metadata["namespaceName"] == conGroup.NamespaceName && pod.Metadata["podName"] == conGroup.ContainerGroupName {
				conGroupIdx = idx
				break
			}
		}

		if conGroupIdx == -1 {
			return
		}

		// update the labels and identities of the container group

		dm.ContainerGroups[conGroupIdx].Labels = []string{}
		dm.ContainerGroups[conGroupIdx].Identities = []string{}

		dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, "namespaceName="+dm.ContainerGroups[conGroupIdx].NamespaceName)
		dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, "containerGroupName="+dm.ContainerGroups[conGroupIdx].ContainerGroupName)

		for k, v := range pod.Labels {
			if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Labels, k+"="+v) {
				dm.ContainerGroups[conGroupIdx].Labels = append(dm.ContainerGroups[conGroupIdx].Labels, k+"="+v)
			}

			if kl.ContainsElement([]string{"controller-revision-hash", "pod-template-hash", "pod-template-generation"}, k) {
				continue
			}

			if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Identities, k+"="+v) {
				dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, k+"="+v)
			}
		}

		// get security policies according to the updated identities
		dm.ContainerGroups[conGroupIdx].SecurityPolicies = dm.GetSecurityPolicies(dm.ContainerGroups[conGroupIdx].Identities)

		// update security policies
		dm.LogFeeder.UpdateSecurityPolicies(action, dm.ContainerGroups[conGroupIdx])

		// enforce security policies
		dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[conGroupIdx])
	} else { // DELETED
		// update security profiles
		dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod)
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

				dm.K8sPodsLock.Lock()

				// create a pod

				pod := tp.K8sPod{}
				pod.HostVolumes = []tp.HostMountedVolume{}

				pod.Metadata = map[string]string{}
				pod.Metadata["namespaceName"] = event.Object.ObjectMeta.Namespace
				pod.Metadata["podName"] = event.Object.ObjectMeta.Name
				pod.Metadata["generation"] = strconv.FormatInt(event.Object.Generation, 10)

				if event.Type == "ADDED" || event.Type == "MODIFIED" {
					exist := false

					for _, k8spod := range dm.K8sPods {
						if k8spod.Metadata["podName"] == pod.Metadata["podName"] &&
							k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] &&
							k8spod.Metadata["generation"] == pod.Metadata["generation"] {
							exist = true
							break
						}
					}

					if exist {
						dm.K8sPodsLock.Unlock()
						continue
					}
				}

				// == AppArmor == //

				pod.Annotations = map[string]string{}
				appArmorAnnotations := map[string]string{}

				for k, v := range event.Object.Annotations {
					pod.Annotations[k] = v

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

				updateAppArmor := false

				for _, container := range event.Object.Spec.Containers {
					if container.Name == "istio-proxy" {
						continue
					}

					if _, ok := appArmorAnnotations[container.Name]; !ok {
						appArmorAnnotations[container.Name] = "kubearmor-" + pod.Metadata["namespaceName"] + "-" + pod.Metadata["podName"] + "-" + container.Name
						updateAppArmor = true
					}
				}

				if dm.RuntimeEnforcer.GetEnforcerType() == "apparmor" && updateAppArmor {
					if pod.Metadata["namespaceName"] != "kube-system" && pod.Metadata["namespaceName"] != "cilium" {
						if event.Type == "ADDED" {
							if len(event.Object.ObjectMeta.OwnerReferences) > 0 && event.Object.ObjectMeta.OwnerReferences[0].Kind == "ReplicaSet" {
								deploymentName := K8s.GetDeploymentNameControllingReplicaSet(pod.Metadata["namespaceName"], event.Object.ObjectMeta.OwnerReferences[0].Name)
								if deploymentName != "" {
									if err := K8s.PatchDeploymentWithAppArmorAnnotations(pod.Metadata["namespaceName"], deploymentName, appArmorAnnotations); err != nil {
										dm.LogFeeder.Errf("Failed to update AppArmor Profiles (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
									} else {
										dm.LogFeeder.Printf("Updated AppArmor Profiles (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
									}
								}
							}
						}

						dm.K8sPodsLock.Unlock()
						continue
					}
				}

				// == SELinux == //

				seLinuxContexts := map[string]string{}
				updateSELinux := false

				// update host-mounted volumes
				for _, v := range event.Object.Spec.Volumes {
					if v.HostPath != nil {
						hostVolume := tp.HostMountedVolume{}
						hostVolume.UsedByContainerReadOnly = map[string]bool{}
						hostVolume.UsedByContainerPath = map[string]string{}
						hostVolume.VolumeName = v.Name
						hostVolume.PathName = v.HostPath.Path
						hostVolume.Type = string(*v.HostPath.Type)
						pod.HostVolumes = append(pod.HostVolumes, hostVolume)
					}
				}

				for _, container := range event.Object.Spec.Containers {
					if pod.Metadata["namespaceName"] == "kube-system" || pod.Metadata["namespaceName"] == "cilium" {
						continue
					}

					// match container volumes to host mounted volume
					for _, containerVolume := range container.VolumeMounts {
						for i, hostVoulme := range pod.HostVolumes {
							if containerVolume.Name == hostVoulme.VolumeName {
								if _, ok := pod.HostVolumes[i].UsedByContainerReadOnly[container.Name]; !ok {
									pod.HostVolumes[i].UsedByContainerReadOnly[container.Name] = containerVolume.ReadOnly
									pod.HostVolumes[i].UsedByContainerPath[container.Name] = containerVolume.MountPath
								}
							}
						}
					}

					if container.SecurityContext == nil || container.SecurityContext.SELinuxOptions == nil || container.SecurityContext.SELinuxOptions.Type == "" {
						if _, ok := seLinuxContexts[container.Name]; !ok {
							deploymentName := K8s.GetDeploymentNameControllingReplicaSet(pod.Metadata["namespaceName"], event.Object.ObjectMeta.OwnerReferences[0].Name)
							if deploymentName == "" {
								continue
							}

							seLinuxType := "kubearmor-" + pod.Metadata["namespaceName"] + "-" + deploymentName + "-" + container.Name
							container.SecurityContext = &v1.SecurityContext{
								SELinuxOptions: &v1.SELinuxOptions{
									Type: seLinuxType + ".process",
								},
							}

							// clear container volume, if not delete volumeMounts, rolling update error
							container.VolumeMounts = []v1.VolumeMount{}

							b, _ := json.Marshal(container)
							seLinuxContexts[container.Name] = string(b)

							updateSELinux = true
						}
					} else {
						if container.SecurityContext != nil && container.SecurityContext.SELinuxOptions != nil {
							if strings.Contains(container.SecurityContext.SELinuxOptions.Type, ".process") {
								if _, ok := pod.Metadata["selinux-"+container.Name]; !ok {
									selinuxContext := strings.Split(container.SecurityContext.SELinuxOptions.Type, ".process")[0]
									pod.Metadata["selinux-"+container.Name] = selinuxContext
								}
							}
						}
					}
				}

				if dm.RuntimeEnforcer.GetEnforcerType() == "selinux" && updateSELinux {
					if pod.Metadata["namespaceName"] != "kube-system" && pod.Metadata["namespaceName"] != "cilium" {
						if event.Type == "ADDED" {
							if len(event.Object.ObjectMeta.OwnerReferences) > 0 && event.Object.ObjectMeta.OwnerReferences[0].Kind == "ReplicaSet" {
								deploymentName := K8s.GetDeploymentNameControllingReplicaSet(pod.Metadata["namespaceName"], event.Object.ObjectMeta.OwnerReferences[0].Name)
								if deploymentName != "" {
									if err := K8s.PatchDeploymentWithSELinuxOptions(pod.Metadata["namespaceName"], deploymentName, seLinuxContexts); err != nil {
										dm.LogFeeder.Errf("Failed to update SELinux security options (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
									} else {
										dm.LogFeeder.Printf("Updated SELinux security options (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
									}
								}
							}
						}

						dm.K8sPodsLock.Unlock()
						continue
					}
				}

				// == //

				pod.Labels = map[string]string{}
				for k, v := range event.Object.Labels {
					pod.Labels[k] = v
				}

				// update the pod into the pod list

				if event.Type == "ADDED" {
					if !kl.ContainsElement(dm.K8sPods, pod) {
						dm.K8sPods = append(dm.K8sPods, pod)
					}
				} else if event.Type == "DELETED" {
					for idx, k8spod := range dm.K8sPods {
						if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
							dm.K8sPods = append(dm.K8sPods[:idx], dm.K8sPods[idx+1:]...)
							break
						}
					}
				} else { // MODIFIED
					targetIdx := -1
					for idx, k8spod := range dm.K8sPods {
						if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
							targetIdx = idx
							break
						}
					}
					if targetIdx != -1 {
						dm.K8sPods[targetIdx] = pod
					}
				}

				dm.K8sPodsLock.Unlock()

				dm.LogFeeder.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event.Type), pod.Metadata["namespaceName"], pod.Metadata["podName"])

				// update a container group corresponding to the pod
				dm.UpdateContainerGroupWithPod(event.Type, pod)
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
			kl.Clone(policy, &secPolicy)
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
			} else if action == "DELETED" {
				// remove the given policy from the security policy list of this container group
				for idxP, policy := range conGroup.SecurityPolicies {
					if reflect.DeepEqual(secPolicy, policy) {
						dm.ContainerGroups[idx].SecurityPolicies = append(dm.ContainerGroups[idx].SecurityPolicies[:idxP], dm.ContainerGroups[idx].SecurityPolicies[idxP+1:]...)
						break
					}
				}
			} else { // MODIFIED
				targetIdx := -1
				for idxP, policy := range conGroup.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						targetIdx = idxP
						break
					}
				}
				if targetIdx != -1 {
					dm.ContainerGroups[idx].SecurityPolicies[targetIdx] = secPolicy
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
			if !K8s.ApplyCustomResourceDefinitions() {
				time.Sleep(time.Second * 1)
				continue
			}
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

				dm.SecurityPoliciesLock.Lock()

				// create a security policy

				secPolicy := tp.SecurityPolicy{}

				secPolicy.Metadata = map[string]string{}
				secPolicy.Metadata["namespaceName"] = event.Object.Metadata.Namespace
				secPolicy.Metadata["policyName"] = event.Object.Metadata.Name
				secPolicy.Metadata["generation"] = strconv.FormatInt(event.Object.Metadata.Generation, 10)

				if event.Type == "ADDED" || event.Type == "MODIFIED" {
					exist := false
					for _, policy := range dm.SecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] &&
							policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] &&
							policy.Metadata["generation"] == secPolicy.Metadata["generation"] {
							exist = true
							break
						}
					}

					if exist {
						dm.SecurityPoliciesLock.Unlock()
						continue
					}
				}

				kl.Clone(event.Object.Spec, &secPolicy.Spec)

				kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Network.MatchProtocols)
				kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Capabilities.MatchCapabilities)

				switch secPolicy.Spec.Action {
				case "allow":
					secPolicy.Spec.Action = "Allow"
				case "block":
					secPolicy.Spec.Action = "Block"
				case "audit":
					secPolicy.Spec.Action = "Audit"
				case "allowwithaudit":
					secPolicy.Spec.Action = "AllowWithAudit"
				case "blockwithaudit":
					secPolicy.Spec.Action = "BlockWithAudit"
				}

				// add identities

				secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, "namespaceName="+event.Object.Metadata.Namespace)

				for k, v := range secPolicy.Spec.Selector.MatchNames {
					if kl.ContainsElement([]string{"containerGroupName", "containerName", "hostName", "imageName"}, k) {
						secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
					}
				}

				for k, v := range secPolicy.Spec.Selector.MatchLabels {
					if !kl.ContainsElement(secPolicy.Spec.Selector.Identities, k+"="+v) {
						secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
					}
				}

				// update a security policy into the policy list

				if event.Type == "ADDED" {
					if !kl.ContainsElement(dm.SecurityPolicies, secPolicy) {
						dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
					}
				} else if event.Type == "DELETED" {
					for idx, policy := range dm.SecurityPolicies {
						if reflect.DeepEqual(secPolicy, policy) {
							dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
							break
						}
					}
				} else { // MODIFIED
					targetIdx := -1
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							targetIdx = idx
							break
						}
					}
					if targetIdx != -1 {
						dm.SecurityPolicies[targetIdx] = secPolicy
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

// UpdateHostSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateHostSecurityPolicy() {
	// get node identities
	nodeIdentities := K8s.GetNodeIdentities()

	dm.HostSecurityPoliciesLock.Lock()
	defer dm.HostSecurityPoliciesLock.Unlock()

	secPolicies := []tp.HostSecurityPolicy{}

	for _, policy := range dm.HostSecurityPolicies {
		if kl.MatchIdentities(policy.Spec.NodeSelector.Identities, nodeIdentities) {
			secPolicies = append(secPolicies, policy)
		}
	}

	// update host security policies
	dm.LogFeeder.UpdateHostSecurityPolicies("UPDATED", secPolicies)

	// enforce host security policies
	dm.RuntimeEnforcer.UpdateHostSecurityPolicies(secPolicies)
}

// WatchHostSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchHostSecurityPolicies() {
	for {
		if K8s.CheckCustomResourceDefinition("kubearmorhostpolicies") {
			if !K8s.ApplyCustomResourceDefinitions() {
				time.Sleep(time.Second * 1)
				continue
			}
		}

		if resp := K8s.WatchK8sHostSecurityPolicies(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sKubeArmorHostPolicyEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				if event.Type == "" {
					continue
				}

				dm.HostSecurityPoliciesLock.Lock()

				// create a host security policy

				secPolicy := tp.HostSecurityPolicy{}

				secPolicy.Metadata = map[string]string{}
				secPolicy.Metadata["policyName"] = event.Object.Metadata.Name
				secPolicy.Metadata["generation"] = strconv.FormatInt(event.Object.Metadata.Generation, 10)

				if event.Type == "ADDED" || event.Type == "MODIFIED" {
					exist := false
					for _, policy := range dm.HostSecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] &&
							policy.Metadata["generation"] == secPolicy.Metadata["generation"] {
							exist = true
							break
						}
					}

					if exist {
						dm.HostSecurityPoliciesLock.Unlock()
						continue
					}
				}

				kl.Clone(event.Object.Spec, &secPolicy.Spec)

				kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Network.MatchProtocols)
				kl.ObjCommaExpandFirstDupOthers(&secPolicy.Spec.Capabilities.MatchCapabilities)

				switch secPolicy.Spec.Action {
				case "allow":
					secPolicy.Spec.Action = "Allow"
				case "block":
					secPolicy.Spec.Action = "Block"
				case "audit":
					secPolicy.Spec.Action = "Audit"
				case "allowwithaudit":
					secPolicy.Spec.Action = "AllowWithAudit"
				case "blockwithaudit":
					secPolicy.Spec.Action = "BlockWithAudit"
				}

				// add identities

				for k, v := range secPolicy.Spec.NodeSelector.MatchNames {
					if kl.ContainsElement([]string{"hostName", "architecture", "osType", "osName", "osVersion", "kernelVersion", "runtimePlatform"}, k) {
						secPolicy.Spec.NodeSelector.Identities = append(secPolicy.Spec.NodeSelector.Identities, k+"="+v)
					}
				}

				for k, v := range secPolicy.Spec.NodeSelector.MatchLabels {
					if !kl.ContainsElement(secPolicy.Spec.NodeSelector.Identities, k+"="+v) {
						secPolicy.Spec.NodeSelector.Identities = append(secPolicy.Spec.NodeSelector.Identities, k+"="+v)
					}
				}

				// update a security policy into the policy list

				if event.Type == "ADDED" {
					if !kl.ContainsElement(dm.HostSecurityPolicies, secPolicy) {
						dm.HostSecurityPolicies = append(dm.HostSecurityPolicies, secPolicy)
					}
				} else if event.Type == "DELETED" {
					for idx, policy := range dm.HostSecurityPolicies {
						if reflect.DeepEqual(secPolicy, policy) {
							dm.HostSecurityPolicies = append(dm.HostSecurityPolicies[:idx], dm.HostSecurityPolicies[idx+1:]...)
							break
						}
					}
				} else { // MODIFIED
					targetIdx := -1
					for idx, policy := range dm.HostSecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							targetIdx = idx
							break
						}
					}
					if targetIdx != -1 {
						dm.HostSecurityPolicies[targetIdx] = secPolicy
					}
				}

				dm.HostSecurityPoliciesLock.Unlock()

				dm.LogFeeder.Printf("Detected a Host Security Policy (%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["policyName"])

				// apply security policies to a host
				dm.UpdateHostSecurityPolicy()
			}
		}
	}
}
