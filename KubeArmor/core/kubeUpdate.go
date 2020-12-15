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

// UpdateContainerGroups Function
func (dm *KubeArmorDaemon) UpdateContainerGroups() {
	containerGroups := map[string]tp.ContainerGroup{}

	for _, container := range dm.Containers {
		namespaceName := container.NamespaceName
		containerGroupName := container.ContainerGroupName
		containerName := container.ContainerName

		// use namespace name and container group name as a key
		key := namespaceName + "|" + containerGroupName

		// if new container
		if oldGroup, ok := containerGroups[key]; !ok {
			newGroup := tp.ContainerGroup{}

			newGroup.NamespaceName = namespaceName
			newGroup.ContainerGroupName = containerGroupName

			newGroup.Labels = container.Labels
			newGroup.Identities = []string{}

			newGroup.Identities = append(newGroup.Identities, "namespaceName="+namespaceName)
			newGroup.Identities = append(newGroup.Identities, "containerGroupName="+containerGroupName)
			newGroup.Identities = append(newGroup.Identities, "containerName="+containerName)
			newGroup.Identities = append(newGroup.Identities, "hostName="+container.HostName)
			newGroup.Identities = append(newGroup.Identities, "imageName="+container.ImageName)

			for _, label := range container.Labels {
				if strings.Contains(label, "com.docker.compose") || strings.Contains(label, "io.kubernetes") {
					continue
				}

				if !kl.ContainsElement(newGroup.Identities, label) {
					newGroup.Identities = append(newGroup.Identities, label)
				}
			}

			if kl.IsK8sEnv() { // kubernetes
				dm.K8sPodsLock.Lock()

				k8sMetadata := K8s.GetK8sPod(dm.K8sPods, namespaceName, containerGroupName)
				for k, v := range k8sMetadata.Labels {
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

				dm.K8sPodsLock.Unlock()
			}

			newGroup.Containers = []string{containerName}

			newGroup.SecurityPolicies = []tp.SecurityPolicy{}
			newGroup.AppArmorProfiles = map[string]string{containerName: container.AppArmorProfile}

			containerGroups[key] = newGroup
		} else { // if exist
			for _, label := range container.Labels {
				if !kl.ContainsElement(oldGroup.Labels, label) {
					oldGroup.Labels = append(oldGroup.Labels, label)
				}

				if strings.Contains(label, "com.docker.compose") || strings.Contains(label, "io.kubernetes") {
					continue
				}

				if !kl.ContainsElement(oldGroup.Identities, label) {
					oldGroup.Identities = append(oldGroup.Identities, label)
				}
			}

			oldGroup.Identities = append(oldGroup.Identities, "containerName="+container.ContainerName)

			if !kl.ContainsElement(oldGroup.Identities, "imageName="+container.ImageName) {
				oldGroup.Identities = append(oldGroup.Identities, "imageName="+container.ImageName)
			}

			if !kl.ContainsElement(oldGroup.Containers, container.ContainerName) {
				oldGroup.Containers = append(oldGroup.Containers, container.ContainerName)
				oldGroup.AppArmorProfiles[container.ContainerName] = container.AppArmorProfile
			}

			containerGroups[key] = oldGroup
		}
	}

	groupList := []tp.ContainerGroup{}
	for _, value := range containerGroups {
		groupList = append(groupList, value)
	}

	dm.ContainerGroupsLock.Lock()
	dm.ContainerGroups = groupList
	dm.ContainerGroupsLock.Unlock()
}

// ================ //
// == Pod Update == //
// ================ //

// UpdateContainerGroupLabels Function
func (dm *KubeArmorDaemon) UpdateContainerGroupLabels(action string, pod tp.K8sPod) {
	// step1. update pods

	dm.K8sPodsLock.Lock()

	if action == "ADDED" {
		if !kl.ContainsElement(dm.K8sPods, pod) {
			dm.K8sPods = append(dm.K8sPods, pod)
		}
	} else if action == "DELETED" {
		for idx, k8spod := range dm.K8sPods {
			if reflect.DeepEqual(pod, k8spod) {
				dm.K8sPods = append(dm.K8sPods[:idx], dm.K8sPods[idx+1:]...)
			}
		}
	} else { // MODIFIED
		for idx, k8spod := range dm.K8sPods {
			if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] &&
				k8spod.Metadata["podName"] == pod.Metadata["podName"] {
				kl.Clone(pod, &dm.K8sPods[idx])
			}
		}
	}

	dm.K8sPodsLock.Unlock()

	// step2. update container groups

	dm.ContainerGroupsLock.Lock()

	if action == "ADDED" {
		for _, conGroup := range dm.ContainerGroups {
			if conGroup.NamespaceName == pod.Metadata["namespaceName"] && conGroup.ContainerGroupName == pod.Metadata["podName"] {
				keyValues := []string{}

				for k, v := range pod.Labels {
					if kl.ContainsElement([]string{"controller-revision-hash", "pod-template-hash", "pod-template-generation"}, k) {
						continue
					}

					keyValues = append(keyValues, k+"="+v)
				}

				// add new labels

				for _, kv := range keyValues {
					if !kl.ContainsElement(conGroup.Labels, kv) {
						conGroup.Labels = append(conGroup.Labels, kv)
					}

					if !kl.ContainsElement(conGroup.Identities, kv) {
						conGroup.Identities = append(conGroup.Identities, kv)
					}
				}
			}
		}
	} else if action == "MODIFIED" {
		for _, conGroup := range dm.ContainerGroups {
			if conGroup.NamespaceName == pod.Metadata["namespaceName"] && conGroup.ContainerGroupName == pod.Metadata["podName"] {
				keyValues := []string{}

				for k, v := range pod.Labels {
					if kl.ContainsElement([]string{"controller-revision-hash", "pod-template-hash", "pod-template-generation"}, k) {
						continue
					}

					keyValues = append(keyValues, k+"="+v)
				}

				// remove old labels

				removedLabels := []string{}

				for _, label := range conGroup.Labels {
					if !kl.ContainsElement(keyValues, label) {
						removedLabels = append(removedLabels, label)
					}
				}

				for _, label := range removedLabels {
					conGroup.Labels = kl.RemoveStrFromSlice(conGroup.Labels, label)
					conGroup.Identities = kl.RemoveStrFromSlice(conGroup.Identities, label)
				}

				// add new labels

				for _, kv := range keyValues {
					if !kl.ContainsElement(conGroup.Labels, kv) {
						conGroup.Labels = append(conGroup.Labels, kv)
					}

					if !kl.ContainsElement(conGroup.Identities, kv) {
						conGroup.Identities = append(conGroup.Identities, kv)
					}
				}
			}
		}
	} else {
		// do nothing (will be removed)
	}

	dm.ContainerGroupsLock.Unlock()
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
						continue
					}
				}

				kl.Clone(event.Object.Annotations, &pod.Annotations)
				kl.Clone(event.Object.Labels, &pod.Labels)

				kg.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event.Type), pod.Metadata["namespaceName"], pod.Metadata["podName"])

				// update labels
				dm.UpdateContainerGroupLabels(event.Type, pod)

				// update security profiles if needed
				dm.RuntimeEnforcer.UpdateSecurityProfiles(event.Type, pod)
			}
		} else {
			time.Sleep(time.Second * 1)
		}
	}
}

// ============================ //
// == Security Policy Update == //
// ============================ //

// UpdateSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateSecurityPolicy(action string, secPolicy tp.SecurityPolicy) {
	// step1. update security policies

	dm.SecurityPoliciesLock.Lock()

	if action == "ADDED" {
		if !kl.ContainsElement(dm.SecurityPolicies, secPolicy) {
			dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
		}
	} else if action == "DELETED" {
		for idx, policy := range dm.SecurityPolicies {
			if reflect.DeepEqual(secPolicy, policy) {
				dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
			}
		}
	} else { // MODIFIED
		for idx, policy := range dm.SecurityPolicies {
			if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] &&
				policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				kl.Clone(secPolicy, &dm.SecurityPolicies[idx])
				break
			}
		}
	}

	dm.SecurityPoliciesLock.Unlock()

	// step2. update container groups

	dm.ContainerGroupsLock.Lock()

	for idx, conGroup := range dm.ContainerGroups {
		// update a security policy
		if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, conGroup.Identities) {
			if action == "ADDED" {
				// add a new security policy if it doesn't exist
				if !kl.ContainsElement(conGroup.SecurityPolicies, secPolicy) {
					conGroup.SecurityPolicies = append(conGroup.SecurityPolicies, secPolicy)
				}
			} else if action == "DELETED" {
				// remove the given policy from the security policy list of this container group
				for idx, policy := range conGroup.SecurityPolicies {
					if reflect.DeepEqual(secPolicy, policy) {
						conGroup.SecurityPolicies = append(conGroup.SecurityPolicies[:idx], conGroup.SecurityPolicies[idx+1:]...)
						break
					}
				}
			} else { // MODIFIED
				for idxP, policy := range conGroup.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] &&
						policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						kl.Clone(secPolicy, &dm.ContainerGroups[idx].SecurityPolicies[idxP])
						break
					}
				}
			}

			kl.Clone(conGroup, &dm.ContainerGroups[idx])

			dm.RuntimeEnforcer.UpdateSecurityPolicies(conGroup)
		}
	}

	dm.ContainerGroupsLock.Unlock()
}

// WatchSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchSecurityPolicies() {
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
							continue
						}
					}

					kl.Clone(event.Object.Spec, &secPolicy.Spec)

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
