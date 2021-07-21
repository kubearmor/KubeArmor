package core

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"

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
		newGroup.Identities = append(newGroup.Identities, "containerGroupName="+newGroup.ContainerGroupName)

		// update labels and identities
		for k, v := range pod.Labels {
			if !kl.ContainsElement(newGroup.Labels, k+"="+v) {
				newGroup.Labels = append(newGroup.Labels, k+"="+v)
			}

			if !kl.ContainsElement(newGroup.Identities, k+"="+v) {
				newGroup.Identities = append(newGroup.Identities, k+"="+v)
			}
		}

		// update container list
		for k := range pod.Containers {
			if !kl.ContainsElement(newGroup.Containers, k) {
				newGroup.Containers = append(newGroup.Containers, k)
			}
		}

		// update flags
		if pod.Annotations["kubearmor-policy"] == "enabled" {
			newGroup.PolicyEnabled = tp.KubeArmorPolicyEnabled
		} else if pod.Annotations["kubearmor-policy"] == "audited" {
			newGroup.PolicyEnabled = tp.KubeArmorPolicyAudited
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
		dm.ContainerGroups[conGroupIdx].Containers = []string{}
		dm.ContainerGroups[conGroupIdx].AppArmorProfiles = map[string]string{}

		dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, "namespaceName="+dm.ContainerGroups[conGroupIdx].NamespaceName)
		dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, "containerGroupName="+dm.ContainerGroups[conGroupIdx].ContainerGroupName)

		for k, v := range pod.Labels {
			if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Labels, k+"="+v) {
				dm.ContainerGroups[conGroupIdx].Labels = append(dm.ContainerGroups[conGroupIdx].Labels, k+"="+v)
			}

			if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Identities, k+"="+v) {
				dm.ContainerGroups[conGroupIdx].Identities = append(dm.ContainerGroups[conGroupIdx].Identities, k+"="+v)
			}
		}

		// update container list
		for k := range pod.Containers {
			if !kl.ContainsElement(dm.ContainerGroups[conGroupIdx].Containers, k) {
				dm.ContainerGroups[conGroupIdx].Containers = append(dm.ContainerGroups[conGroupIdx].Containers, k)
			}
		}

		// update flags

		prevPolicyEnabled := dm.ContainerGroups[conGroupIdx].PolicyEnabled

		if pod.Annotations["kubearmor-policy"] == "enabled" {
			dm.ContainerGroups[conGroupIdx].PolicyEnabled = tp.KubeArmorPolicyEnabled
		} else if pod.Annotations["kubearmor-policy"] == "audited" {
			dm.ContainerGroups[conGroupIdx].PolicyEnabled = tp.KubeArmorPolicyAudited
		} else {
			dm.ContainerGroups[conGroupIdx].PolicyEnabled = tp.KubeArmorPolicyDisabled
		}

		// parse annotations and set flags

		dm.ContainerGroups[conGroupIdx].ProcessVisibilityEnabled = false
		dm.ContainerGroups[conGroupIdx].FileVisibilityEnabled = false
		dm.ContainerGroups[conGroupIdx].NetworkVisibilityEnabled = false
		dm.ContainerGroups[conGroupIdx].CapabilitiesVisibilityEnabled = false

		for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
			if visibility == "process" {
				dm.ContainerGroups[conGroupIdx].ProcessVisibilityEnabled = true
			} else if visibility == "file" {
				dm.ContainerGroups[conGroupIdx].FileVisibilityEnabled = true
			} else if visibility == "network" {
				dm.ContainerGroups[conGroupIdx].NetworkVisibilityEnabled = true
			} else if visibility == "capabilities" {
				dm.ContainerGroups[conGroupIdx].CapabilitiesVisibilityEnabled = true
			}
		}

		// update containers
		dm.ContainersLock.Lock()
		for _, containerID := range dm.ContainerGroups[conGroupIdx].Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = dm.ContainerGroups[conGroupIdx].NamespaceName
			container.ContainerGroupName = dm.ContainerGroups[conGroupIdx].ContainerGroupName
			container.ContainerName = pod.Containers[containerID]

			container.PolicyEnabled = dm.ContainerGroups[conGroupIdx].PolicyEnabled

			container.ProcessVisibilityEnabled = dm.ContainerGroups[conGroupIdx].ProcessVisibilityEnabled
			container.FileVisibilityEnabled = dm.ContainerGroups[conGroupIdx].FileVisibilityEnabled
			container.NetworkVisibilityEnabled = dm.ContainerGroups[conGroupIdx].NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = dm.ContainerGroups[conGroupIdx].CapabilitiesVisibilityEnabled

			dm.ContainerGroups[conGroupIdx].AppArmorProfiles[containerID] = container.AppArmorProfile

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		if prevPolicyEnabled != tp.KubeArmorPolicyEnabled && dm.ContainerGroups[conGroupIdx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// initialize and register security profiles
			dm.RuntimeEnforcer.UpdateSecurityProfiles("ADDED", pod, true)
		}

		// get security policies according to the updated identities
		dm.ContainerGroups[conGroupIdx].SecurityPolicies = dm.GetSecurityPolicies(dm.ContainerGroups[conGroupIdx].Identities)

		// update security policies
		dm.LogFeeder.UpdateSecurityPolicies(action, dm.ContainerGroups[conGroupIdx])

		// enforce security policies
		dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[conGroupIdx])

	} else { // DELETED
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

		if dm.ContainerGroups[conGroupIdx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// initialize and unregister security profiles
			dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod, true)
		}

		// remove container group
		dm.ContainerGroups = append(dm.ContainerGroups[:conGroupIdx], dm.ContainerGroups[conGroupIdx+1:]...)
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

				if dm.EnableEnforcerPerPod {
					if _, ok := pod.Annotations["kubearmor-policy"]; ok {
						if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" {
							pod.Annotations["kubearmor-policy"] = "audited"
						}
					} else {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				} else { // EnableEnforcerAll
					if _, ok := pod.Annotations["kubearmor-policy"]; ok {
						if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" && pod.Annotations["kubearmor-policy"] != "audited" {
							pod.Annotations["kubearmor-policy"] = "enabled"
						}
					} else {
						pod.Annotations["kubearmor-policy"] = "enabled"
					}
				}

				// == //

				// exception: coredns
				if val, ok := pod.Labels["k8s-app"]; ok {
					if val == "kube-dns" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				}

				// exception: cilium-operator
				if val, ok := pod.Labels["io.cilium/app"]; ok {
					if val == "operator" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				}

				// exception: calico-kube-controllers
				if val, ok := pod.Labels["k8s-app"]; ok {
					if val == "calico-kube-controllers" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				}

				// == //

				if dm.RuntimeEnforcer.IsEnabled() {
					if lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm"); err == nil {
						// exception: no AppArmor
						if !strings.Contains(string(lsm), "apparmor") {
							if pod.Annotations["kubearmor-policy"] == "enabled" {
								pod.Annotations["kubearmor-policy"] = "audited"
							}
						}
					}
				} else { // No LSM
					if pod.Annotations["kubearmor-policy"] == "enabled" {
						pod.Annotations["kubearmor-policy"] = "audited"
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

							if reflect.DeepEqual(k8spod.Annotations, pod.Annotations) &&
								reflect.DeepEqual(k8spod.Labels, pod.Labels) &&
								reflect.DeepEqual(k8spod.Containers, pod.Containers) {
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

				// == SELinux == //

				if pod.Annotations["kubearmor-policy"] == "enabled" {
					pod.HostVolumes = []tp.HostMountedVolume{}
					seLinuxContexts := map[string]string{}
					updateSELinux := false

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

						if container.SecurityContext != nil && container.SecurityContext.SELinuxOptions != nil {
							if strings.Contains(container.SecurityContext.SELinuxOptions.Type, ".process") {
								if _, ok := pod.Metadata["selinux-"+container.Name]; !ok {
									selinuxContext := strings.Split(container.SecurityContext.SELinuxOptions.Type, ".process")[0]
									pod.Metadata["selinux-"+container.Name] = selinuxContext
								}
							}
						}
					}

					for _, container := range event.Object.Spec.Containers {
						if container.SecurityContext == nil || container.SecurityContext.SELinuxOptions == nil || container.SecurityContext.SELinuxOptions.Type == "" {
							if _, ok1 := seLinuxContexts[container.Name]; !ok1 {
								if _, ok2 := pod.Metadata["deploymentName"]; !ok2 {
									continue
								}

								container.SecurityContext = &v1.SecurityContext{
									SELinuxOptions: &v1.SELinuxOptions{
										Type: "kubearmor-" + pod.Metadata["namespaceName"] + "-" + pod.Metadata["deploymentName"] + "-" + container.Name + ".process",
									},
								}

								// clear container volume, if not delete volumeMounts, rolling update error
								container.VolumeMounts = []v1.VolumeMount{}

								b, _ := json.Marshal(container)
								seLinuxContexts[container.Name] = string(b)

								// set update flag
								updateSELinux = true
							}
						}
					}

					// if no selinux annotations but kubearmor-policy is enabled, add selinux annotations
					if dm.RuntimeEnforcer.GetEnforcerType() == "selinux" {
						if updateSELinux && (event.Type == "ADDED" || event.Type == "MODIFIED") {
							if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
								if err := K8s.PatchDeploymentWithSELinuxOptions(pod.Metadata["namespaceName"], deploymentName, seLinuxContexts); err != nil {
									dm.LogFeeder.Errf("Failed to update SELinux security options (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
								} else {
									dm.LogFeeder.Printf("Patched SELinux security options (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
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

				if pod.Annotations["kubearmor-policy"] != "patched" {
					dm.LogFeeder.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event.Type), pod.Metadata["namespaceName"], pod.Metadata["podName"])
				}

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
			if err := kl.Clone(policy, &secPolicy); err != nil {
				fmt.Println("Failed to clone a policy")
			}
			secPolicies = append(secPolicies, secPolicy)
		}
	}

	return secPolicies
}

// UpdateSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateSecurityPolicy(action string, secPolicy tp.SecurityPolicy, status string) {
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

			if status == "" || status == "OK" {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[idx])
			}
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
				case "block":
					secPolicy.Spec.Action = "Block"
				case "audit":
					secPolicy.Spec.Action = "Audit"
				case "allowwithaudit":
					secPolicy.Spec.Action = "AllowWithAudit"
				case "blockwithaudit":
					secPolicy.Spec.Action = "BlockWithAudit"
				case "":
					secPolicy.Spec.Action = "Block" // by default
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

				if len(secPolicy.Spec.SELinux.MatchMountedVolumes) > 0 {
					for idx, se := range secPolicy.Spec.SELinux.MatchMountedVolumes {
						if se.Severity == 0 {
							if secPolicy.Spec.SELinux.Severity != 0 {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Severity = secPolicy.Spec.SELinux.Severity
							} else {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Severity = secPolicy.Spec.Severity
							}
						}

						if len(se.Tags) == 0 {
							if len(secPolicy.Spec.SELinux.Tags) > 0 {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Tags = secPolicy.Spec.SELinux.Tags
							} else {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Tags = secPolicy.Spec.Tags
							}
						}

						if len(se.Message) == 0 {
							if len(secPolicy.Spec.SELinux.Message) > 0 {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Message = secPolicy.Spec.SELinux.Message
							} else {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Message = secPolicy.Spec.Message
							}
						}

						if len(se.Action) == 0 {
							if len(secPolicy.Spec.SELinux.Action) > 0 {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Action = secPolicy.Spec.SELinux.Action
							} else {
								secPolicy.Spec.SELinux.MatchMountedVolumes[idx].Action = secPolicy.Spec.Action
							}
						}
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
				dm.UpdateSecurityPolicy(event.Type, secPolicy, event.Object.Status.PolicyStatus)
			}
		}
	}
}

// UpdateHostSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateHostSecurityPolicy(status string) {
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

	if status == "" || status == "OK" {
		// enforce host security policies
		dm.RuntimeEnforcer.UpdateHostSecurityPolicies(secPolicies)
	}
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
				case "block":
					secPolicy.Spec.Action = "Block"
				case "audit":
					secPolicy.Spec.Action = "Audit"
				case "allowwithaudit":
					secPolicy.Spec.Action = "AllowWithAudit"
				case "blockwithaudit":
					secPolicy.Spec.Action = "BlockWithAudit"
				case "":
					secPolicy.Spec.Action = "Block" // by default
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
				} else if len(secPolicy.Spec.Process.MatchDirectories) > 0 {
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
				} else if len(secPolicy.Spec.Process.MatchPatterns) > 0 {
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
				} else if len(secPolicy.Spec.File.MatchDirectories) > 0 {
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
				} else if len(secPolicy.Spec.File.MatchPatterns) > 0 {
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
				dm.UpdateHostSecurityPolicy(event.Object.Status.PolicyStatus)
			}
		}
	}
}
