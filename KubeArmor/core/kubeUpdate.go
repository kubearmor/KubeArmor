package core

import (
	"encoding/json"
	"io"
	"reflect"
	"strconv"
	"strings"
	"time"

	kl "github.com/accuknox/KubeArmor/KubeArmor/common"
	kg "github.com/accuknox/KubeArmor/KubeArmor/log"
	tp "github.com/accuknox/KubeArmor/KubeArmor/types"
)

// ============================ //
// == Container Group Update == //
// ============================ //

// UpdateContainerGroupWithContainer Function
func (dm *KubeArmorDaemon) UpdateContainerGroupWithContainer(action string, container tp.Container) {
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
		kg.Errf("No container group (%s/%s) for a container (%s)", container.NamespaceName, container.ContainerGroupName, container.ContainerID[:12])
		return
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
	}

	// enforce the security policy

	dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[conGroupIdx])
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

		// update security policies with the updated identities

		dm.ContainerGroups[conGroupIdx].SecurityPolicies = dm.GetSecurityPolicies(dm.ContainerGroups[conGroupIdx].Identities)

		// enforce the security policy

		dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[conGroupIdx])
	} else { // DELETED
		// update security profiles

		dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod)
	}
}

// WatchK8sPods Function
func (dm *KubeArmorDaemon) WatchK8sPods() {
	// dm.WgDaemon.Add(1)
	// defer dm.WgDaemon.Done()

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

				pod.Annotations = map[string]string{}
				for k, v := range event.Object.Annotations {
					pod.Annotations[k] = v
				}

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

				kg.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event.Type), pod.Metadata["namespaceName"], pod.Metadata["podName"])

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
	secPolicies := []tp.SecurityPolicy{}

	dm.SecurityPoliciesLock.Lock()

	for _, policy := range dm.SecurityPolicies {
		if kl.MatchIdentities(policy.Spec.Selector.Identities, identities) {
			secPolicy := tp.SecurityPolicy{}
			kl.Clone(policy, &secPolicy)
			secPolicies = append(secPolicies, secPolicy)
		}
	}

	dm.SecurityPoliciesLock.Unlock()

	return secPolicies
}

// UpdateSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateSecurityPolicy(action string, secPolicy tp.SecurityPolicy) {
	dm.ContainerGroupsLock.Lock()

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

			// enforce the security policy
			dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.ContainerGroups[idx])
		}
	}

	dm.ContainerGroupsLock.Unlock()
}

// WatchSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchSecurityPolicies() {
	// dm.WgDaemon.Add(1)
	// defer dm.WgDaemon.Done()

	for {
		if K8s.CheckCustomResourceDefinition("kubearmorpolicies") {
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

					kg.Printf("Detected a Security Policy (%s/%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

					// apply security policies to containers

					dm.UpdateSecurityPolicy(event.Type, secPolicy)
				}
			}
		} else {
			time.Sleep(time.Second * 1)
		}
	}
}
