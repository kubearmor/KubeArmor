package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"reflect"
	"strconv"
	"strings"
	"time"

	v1 "k8s.io/api/core/v1"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================ //
// == Pod Update == //
// ================ //

// UpdateEndPointWithPod Function
func (dm *KubeArmorDaemon) UpdateEndPointWithPod(action string, pod tp.K8sPod) {
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	if action == "ADDED" {
		// create a new endpoint

		newPoint := tp.EndPoint{}

		newPoint.NamespaceName = pod.Metadata["namespaceName"]
		newPoint.EndPointName = pod.Metadata["podName"]

		newPoint.Labels = []string{}
		newPoint.Identities = []string{}
		newPoint.Containers = []string{}
		newPoint.AppArmorProfiles = map[string]string{}

		newPoint.Identities = append(newPoint.Identities, "namespaceName="+pod.Metadata["namespaceName"])

		// update labels and identities
		for k, v := range pod.Labels {
			if !kl.ContainsElement(newPoint.Labels, k+"="+v) {
				newPoint.Labels = append(newPoint.Labels, k+"="+v)
			}

			if !kl.ContainsElement(newPoint.Identities, k+"="+v) {
				newPoint.Identities = append(newPoint.Identities, k+"="+v)
			}
		}

		// update container list
		for k := range pod.Containers {
			if !kl.ContainsElement(newPoint.Containers, k) {
				newPoint.Containers = append(newPoint.Containers, k)
			}
		}

		// update flags
		if pod.Annotations["kubearmor-policy"] == "enabled" {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
		} else if pod.Annotations["kubearmor-policy"] == "audited" {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
		} else {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyDisabled
		}

		// parse annotations and set flags
		for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
			if visibility == "process" {
				newPoint.ProcessVisibilityEnabled = true
			} else if visibility == "file" {
				newPoint.FileVisibilityEnabled = true
			} else if visibility == "network" {
				newPoint.NetworkVisibilityEnabled = true
			} else if visibility == "capabilities" {
				newPoint.CapabilitiesVisibilityEnabled = true
			}
		}

		// update containers
		dm.ContainersLock.Lock()
		for _, containerID := range newPoint.Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = newPoint.NamespaceName
			container.EndPointName = newPoint.EndPointName
			container.ContainerName = pod.Containers[containerID]

			container.PolicyEnabled = newPoint.PolicyEnabled

			container.ProcessVisibilityEnabled = newPoint.ProcessVisibilityEnabled
			container.FileVisibilityEnabled = newPoint.FileVisibilityEnabled
			container.NetworkVisibilityEnabled = newPoint.NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = newPoint.CapabilitiesVisibilityEnabled

			newPoint.AppArmorProfiles[containerID] = container.AppArmorProfile

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		// update selinux profile names to the endpoint
		newPoint.SELinuxProfiles = map[string]string{}
		for k, v := range pod.Metadata {
			if strings.HasPrefix(k, "selinux-") {
				contName := strings.Split(k, "selinux-")[1]
				newPoint.SELinuxProfiles[contName] = v
			}
		}

		// update host-side volume mounted
		newPoint.HostVolumes = []tp.HostVolumeMount{}
		newPoint.HostVolumes = append(newPoint.HostVolumes, pod.HostVolumes...)

		// update security policies with the identities
		newPoint.SecurityPolicies = dm.GetSecurityPolicies(newPoint.Identities)

		// add the endpoint into the endpoint list
		dm.EndPoints = append(dm.EndPoints, newPoint)

		if newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
			// create and register security profiles
			dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod, true)
		}

		// update security policies
		dm.LogFeeder.UpdateSecurityPolicies(action, newPoint)

		// enforce security policies
		dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)

	} else if action == "MODIFIED" {
		for idx, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				// update the labels and identities of the endpoint

				dm.EndPoints[idx].Labels = []string{}
				dm.EndPoints[idx].Identities = []string{}
				dm.EndPoints[idx].Containers = []string{}
				dm.EndPoints[idx].AppArmorProfiles = map[string]string{}

				dm.EndPoints[idx].Identities = append(dm.EndPoints[idx].Identities, "namespaceName="+pod.Metadata["namespaceName"])

				for k, v := range pod.Labels {
					if !kl.ContainsElement(dm.EndPoints[idx].Labels, k+"="+v) {
						dm.EndPoints[idx].Labels = append(dm.EndPoints[idx].Labels, k+"="+v)
					}

					if !kl.ContainsElement(dm.EndPoints[idx].Identities, k+"="+v) {
						dm.EndPoints[idx].Identities = append(dm.EndPoints[idx].Identities, k+"="+v)
					}
				}

				// update container list
				for k := range pod.Containers {
					if !kl.ContainsElement(dm.EndPoints[idx].Containers, k) {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, k)
					}
				}

				// update flags

				prevPolicyEnabled := dm.EndPoints[idx].PolicyEnabled

				if pod.Annotations["kubearmor-policy"] == "enabled" {
					dm.EndPoints[idx].PolicyEnabled = tp.KubeArmorPolicyEnabled
				} else if pod.Annotations["kubearmor-policy"] == "audited" {
					dm.EndPoints[idx].PolicyEnabled = tp.KubeArmorPolicyAudited
				} else {
					dm.EndPoints[idx].PolicyEnabled = tp.KubeArmorPolicyDisabled
				}

				// parse annotations and set flags

				dm.EndPoints[idx].ProcessVisibilityEnabled = false
				dm.EndPoints[idx].FileVisibilityEnabled = false
				dm.EndPoints[idx].NetworkVisibilityEnabled = false
				dm.EndPoints[idx].CapabilitiesVisibilityEnabled = false

				for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
					if visibility == "process" {
						dm.EndPoints[idx].ProcessVisibilityEnabled = true
					} else if visibility == "file" {
						dm.EndPoints[idx].FileVisibilityEnabled = true
					} else if visibility == "network" {
						dm.EndPoints[idx].NetworkVisibilityEnabled = true
					} else if visibility == "capabilities" {
						dm.EndPoints[idx].CapabilitiesVisibilityEnabled = true
					}
				}

				// update containers
				dm.ContainersLock.Lock()
				for _, containerID := range dm.EndPoints[idx].Containers {
					container := dm.Containers[containerID]

					container.NamespaceName = dm.EndPoints[idx].NamespaceName
					container.EndPointName = dm.EndPoints[idx].EndPointName
					container.ContainerName = pod.Containers[containerID]

					container.PolicyEnabled = dm.EndPoints[idx].PolicyEnabled

					container.ProcessVisibilityEnabled = dm.EndPoints[idx].ProcessVisibilityEnabled
					container.FileVisibilityEnabled = dm.EndPoints[idx].FileVisibilityEnabled
					container.NetworkVisibilityEnabled = dm.EndPoints[idx].NetworkVisibilityEnabled
					container.CapabilitiesVisibilityEnabled = dm.EndPoints[idx].CapabilitiesVisibilityEnabled

					dm.EndPoints[idx].AppArmorProfiles[containerID] = container.AppArmorProfile

					dm.Containers[containerID] = container
				}
				dm.ContainersLock.Unlock()

				if prevPolicyEnabled != tp.KubeArmorPolicyEnabled && dm.EndPoints[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// initialize and register security profiles
					dm.RuntimeEnforcer.UpdateSecurityProfiles("ADDED", pod, true)
				}

				// get security policies according to the updated identities
				dm.EndPoints[idx].SecurityPolicies = dm.GetSecurityPolicies(dm.EndPoints[idx].Identities)

				// update security policies
				dm.LogFeeder.UpdateSecurityPolicies(action, dm.EndPoints[idx])

				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.EndPoints[idx])

				break
			}
		}

	} else { // DELETED
		for idx, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				if dm.EndPoints[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// initialize and unregister security profiles
					dm.RuntimeEnforcer.UpdateSecurityProfiles(action, pod, true)
				}

				// remove endpoint
				dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)

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
					pod.HostVolumes = []tp.HostVolumeMount{}
					seLinuxContexts := map[string]string{}
					updateSELinux := false

					for _, v := range event.Object.Spec.Volumes {
						if v.HostPath != nil {
							hostVolume := tp.HostVolumeMount{}

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
				}

				// update a endpoint corresponding to the pod
				dm.UpdateEndPointWithPod(event.Type, pod)
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
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	for idx, endPoint := range dm.EndPoints {
		// update a security policy
		if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) {
			if action == "ADDED" {
				// add a new security policy if it doesn't exist
				if !kl.ContainsElement(endPoint.SecurityPolicies, secPolicy) {
					dm.EndPoints[idx].SecurityPolicies = append(dm.EndPoints[idx].SecurityPolicies, secPolicy)
				}
			} else if action == "MODIFIED" {
				for idxP, policy := range endPoint.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						dm.EndPoints[idx].SecurityPolicies[idxP] = secPolicy
						break
					}
				}
			} else if action == "DELETED" {
				// remove the given policy from the security policy list of this endpoint
				for idxP, policy := range endPoint.SecurityPolicies {
					if reflect.DeepEqual(secPolicy, policy) {
						dm.EndPoints[idx].SecurityPolicies = append(dm.EndPoints[idx].SecurityPolicies[:idxP], dm.EndPoints[idx].SecurityPolicies[idxP+1:]...)
						break
					}
				}
			}

			// update security policies
			dm.LogFeeder.UpdateSecurityPolicies("UPDATED", dm.EndPoints[idx])

			// enforce security policies
			dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.EndPoints[idx])
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

				if event.Object.Status.Status != "" && event.Object.Status.Status != "OK" {
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

				if len(secPolicy.Spec.SELinux.MatchVolumeMounts) > 0 {
					for idx, se := range secPolicy.Spec.SELinux.MatchVolumeMounts {
						if se.Severity == 0 {
							if secPolicy.Spec.SELinux.Severity != 0 {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Severity = secPolicy.Spec.SELinux.Severity
							} else {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Severity = secPolicy.Spec.Severity
							}
						}

						if len(se.Tags) == 0 {
							if len(secPolicy.Spec.SELinux.Tags) > 0 {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Tags = secPolicy.Spec.SELinux.Tags
							} else {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Tags = secPolicy.Spec.Tags
							}
						}

						if len(se.Message) == 0 {
							if len(secPolicy.Spec.SELinux.Message) > 0 {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Message = secPolicy.Spec.SELinux.Message
							} else {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Message = secPolicy.Spec.Message
							}
						}

						if len(se.Action) == 0 {
							if len(secPolicy.Spec.SELinux.Action) > 0 {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Action = secPolicy.Spec.SELinux.Action
							} else {
								secPolicy.Spec.SELinux.MatchVolumeMounts[idx].Action = secPolicy.Spec.Action
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

// UpdateHostSecurityPolicies Function
func (dm *KubeArmorDaemon) UpdateHostSecurityPolicies() {
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
		if !K8s.CheckCustomResourceDefinition("kubearmorhostpolicies") {
			time.Sleep(time.Second * 1)
			continue
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

				if event.Object.Status.Status != "" && event.Object.Status.Status != "OK" {
					continue
				}

				dm.HostSecurityPoliciesLock.Lock()

				// create a host security policy

				secPolicy := tp.HostSecurityPolicy{}

				secPolicy.Metadata = map[string]string{}
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
				} else if event.Type == "MODIFIED" {
					for idx, policy := range dm.HostSecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.HostSecurityPolicies[idx] = secPolicy
							break
						}
					}
				} else if event.Type == "DELETED" {
					for idx, policy := range dm.HostSecurityPolicies {
						if reflect.DeepEqual(secPolicy, policy) {
							dm.HostSecurityPolicies = append(dm.HostSecurityPolicies[:idx], dm.HostSecurityPolicies[idx+1:]...)
							break
						}
					}
				}

				dm.HostSecurityPoliciesLock.Unlock()

				dm.LogFeeder.Printf("Detected a Host Security Policy (%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["policyName"])

				// apply security policies to a host
				dm.UpdateHostSecurityPolicies()
			}
		}
	}
}

// ================================= //
// == Macro / Audit Policy Update == //
// ================================= //

func k8sAuditPolicyMergeMacro(k8sAuditPolicySpec *tp.K8sAuditPolicySpec, macroName string, macroValue string) {
	expandMacroField := func(field *string, src string, dst string) {
		if *field == src {
			*field = dst
		}
	}

	expandMacroField(&k8sAuditPolicySpec.Severity, macroName, macroValue)
	expandMacroField(&k8sAuditPolicySpec.Message, macroName, macroValue)

	for i := 0; i < len(k8sAuditPolicySpec.Tags); i++ {
		expandMacroField(&k8sAuditPolicySpec.Tags[i], macroName, macroValue)
	}

	for i := 0; i < len(k8sAuditPolicySpec.AuditRules); i++ {
		expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Process, macroName, macroValue)
		expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Severity, macroName, macroValue)
		expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Message, macroName, macroValue)

		for j := 0; j < len(k8sAuditPolicySpec.AuditRules[i].Events); j++ {
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Probe, macroName, macroValue)
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Rate, macroName, macroValue)

			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Path, macroName, macroValue)
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Directory, macroName, macroValue)
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Mode, macroName, macroValue)

			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Protocol, macroName, macroValue)
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Ipv4Addr, macroName, macroValue)
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Ipv6Addr, macroName, macroValue)
			expandMacroField(&k8sAuditPolicySpec.AuditRules[i].Events[j].Port, macroName, macroValue)
		}
	}
}

func k8sAuditPolicyConvert(k8sAuditPolicySpec tp.K8sAuditPolicySpec) ([]tp.KubeArmorAuditPolicy, error) {
	var err error
	var defaultSeverity int64
	var defaultMessage string
	var defaultTags []string
	var auditPolicies []tp.KubeArmorAuditPolicy
	auditPolicies = make([]tp.KubeArmorAuditPolicy, len(k8sAuditPolicySpec.AuditRules))

	if k8sAuditPolicySpec.Severity != "" {
		if defaultSeverity, err = strconv.ParseInt(k8sAuditPolicySpec.Severity, 0, 32); err != nil {
			message := fmt.Sprintf("Cannot convert '%v' (K8sAuditPolicySpec.Severity) to int", k8sAuditPolicySpec.Severity)
			return nil, errors.New(message)
		}
	} else {
		defaultSeverity = 1
	}

	defaultMessage = k8sAuditPolicySpec.Message
	defaultTags = make([]string, len(k8sAuditPolicySpec.Tags))
	copy(defaultTags, k8sAuditPolicySpec.Tags)

	for i, rule := range k8sAuditPolicySpec.AuditRules {
		var severity int64

		if rule.Process != "" {
			auditPolicies[i].Process = rule.Process
		} else {
			auditPolicies[i].Process = "*"
		}

		if rule.Message != "" {
			auditPolicies[i].Message = rule.Message
		} else {
			auditPolicies[i].Message = defaultMessage
		}

		if len(rule.Tags) > 0 {
			auditPolicies[i].Tags = make([]string, len(rule.Tags))
			copy(auditPolicies[i].Tags, rule.Tags)
		} else {
			auditPolicies[i].Tags = make([]string, len(defaultTags))
			copy(auditPolicies[i].Tags, defaultTags)
		}

		if rule.Severity != "" {
			if severity, err = strconv.ParseInt(rule.Severity, 0, 32); err != nil {
				message := fmt.Sprintf("Cannot convert '%v' (K8sAuditPolicySpec.AuditRules[%v].Severity) to int", rule.Severity, i)
				return nil, errors.New(message)
			}
			auditPolicies[i].Severity = int(severity)
		} else {
			auditPolicies[i].Severity = int(defaultSeverity)
		}

		auditPolicies[i].Events = make([]tp.AuditEventType, len(rule.Events))
		for j, ruleEvent := range rule.Events {
			var number int64

			auditPolicies[i].Events[j].Probe = ruleEvent.Probe
			auditPolicies[i].Events[j].Rate = ruleEvent.Rate

			auditPolicies[i].Events[j].Protocol = ruleEvent.Protocol
			auditPolicies[i].Events[j].Ipv4Addr = ruleEvent.Ipv4Addr
			auditPolicies[i].Events[j].Ipv6Addr = ruleEvent.Ipv6Addr

			auditPolicies[i].Events[j].Path = ruleEvent.Path
			auditPolicies[i].Events[j].Directory = ruleEvent.Directory

			auditPolicies[i].Events[j].Severity = auditPolicies[i].Severity
			auditPolicies[i].Events[j].Tags = auditPolicies[i].Tags
			auditPolicies[i].Events[j].Message = auditPolicies[i].Message

			if ruleEvent.Mode != "" {
				if number, err = strconv.ParseInt(ruleEvent.Mode, 0, 32); err != nil {
					message := fmt.Sprintf("Cannot convert '%v' (K8sAuditPolicySpec.AuditRules[%v].Events[%v].Mode) to int", ruleEvent.Mode, i, j)
					return nil, errors.New(message)
				}
				auditPolicies[i].Events[j].Mode = int(number)
			}

			if ruleEvent.Port != "" {
				if number, err = strconv.ParseInt(ruleEvent.Port, 0, 32); err != nil {
					message := fmt.Sprintf("Cannot convert '%v' (K8sAuditPolicySpec.AuditRules[%v].Events[%v].Port) to int", ruleEvent.Port, i, j)
					return nil, errors.New(message)
				}
				auditPolicies[i].Events[j].Port = int(number)
			}
		}
	}

	return auditPolicies, nil
}

// UpdateAuditPolicies Function
func (dm *KubeArmorDaemon) UpdateAuditPolicies() {
	var err error
	var auditPolicies []tp.KubeArmorAuditPolicy
	k8sAuditPolicySpec := tp.K8sAuditPolicySpec{}

	// garbage collect old kubearmor policies
	dm.AuditPoliciesLock.Lock()
	dm.AuditPolicies = make(map[string]tp.KubeArmorAuditPolicy)
	dm.AuditPoliciesLock.Unlock()

	dm.K8sAuditPoliciesLock.Lock()
	for _, k8sPolicy := range dm.K8sAuditPolicies {
		// clone spec
		if err = kl.Clone(k8sPolicy.Spec, &k8sAuditPolicySpec); err != nil {
			dm.LogFeeder.Printf("Failed to clone spec for k8sPolicy %s", k8sPolicy.Metadata.Name)
			continue
		}

		// merge macros
		for _, k8sMacros := range dm.K8sMacros {
			if k8sPolicy.Metadata.Namespace == k8sMacros.Metadata.Namespace {
				dm.K8sMacrosLock.Lock()
				for _, macro := range k8sMacros.Spec.Macros {
					k8sAuditPolicyMergeMacro(&k8sAuditPolicySpec, macro.Name, macro.Value)
				}
				dm.K8sMacrosLock.Unlock()
			}
		}

		for i := 0; i < len(k8sAuditPolicySpec.AuditRules); i++ {
			// expand comma separated process name
			auditRule := k8sAuditPolicySpec.AuditRules[i]
			procNames := strings.Split(auditRule.Process, ",")
			k8sAuditPolicySpec.AuditRules[i].Process = procNames[0]

			for _, name := range procNames[1:] {
				if name[0] == ' ' {
					name = name[1:]
				}

				newAuditRule := auditRule
				newAuditRule.Process = name
				newAuditRule.Events = make([]tp.K8sEventType, len(auditRule.Events))
				copy(newAuditRule.Events, auditRule.Events)
				k8sAuditPolicySpec.AuditRules = append(k8sAuditPolicySpec.AuditRules, newAuditRule)
			}

			// expand comma separated probes
			for j := 0; j < len(k8sAuditPolicySpec.AuditRules[i].Events); j++ {
				event := k8sAuditPolicySpec.AuditRules[i].Events[j]
				probeNames := strings.Split(event.Probe, ",")
				k8sAuditPolicySpec.AuditRules[i].Events[j].Probe = probeNames[0]

				for _, name := range probeNames[1:] {
					if name[0] == ' ' {
						name = name[1:]
					}

					newEvent := event
					newEvent.Probe = name
					k8sAuditPolicySpec.AuditRules[i].Events = append(k8sAuditPolicySpec.AuditRules[i].Events, newEvent)
				}
			}
		}

		// convert k8sAuditPolicy spec
		// skip (and alert) invalid conversions
		if auditPolicies, err = k8sAuditPolicyConvert(k8sAuditPolicySpec); err != nil {
			dm.LogFeeder.Printf("Failed to convert K8sAuditPolicySpec: %v", err)
			continue
		}

		// aggregate audit policies
		dm.AuditPoliciesLock.Lock()
		for _, auditPolicy := range auditPolicies {
			key := fmt.Sprintf("%v:%v", k8sPolicy.Metadata.Namespace, auditPolicy.Process)

			// if the same namespace:process exists, merge events
			if _, ok := dm.AuditPolicies[key]; ok {
				mapEntry := dm.AuditPolicies[key]

				// remove globals values for severity, tags and message
				mapEntry.Severity = 1
				mapEntry.Tags = []string{}
				mapEntry.Message = ""

				// merge events
				mapEntry.Events = append(mapEntry.Events, auditPolicy.Events...)
				dm.AuditPolicies[key] = mapEntry
			} else {
				dm.AuditPolicies[key] = auditPolicy
			}
		}
		dm.AuditPoliciesLock.Unlock()
	}

	dm.K8sAuditPoliciesLock.Unlock()

	dm.EventAuditor.UpdateEntryPoints(&dm.AuditPolicies, &dm.AuditPoliciesLock)
	dm.EventAuditor.UpdateProcessMaps(&dm.AuditPolicies, &dm.AuditPoliciesLock)
}

func waitCustomResourceDefinition(name string) {
	for !K8s.CheckCustomResourceDefinition(name) {
		time.Sleep(time.Second * 1)
		continue
	}
}

func (dm *KubeArmorDaemon) decodeAuditPolicy(decoder *json.Decoder) {
	for {
		event := tp.K8sKubeArmorAuditPolicyEvent{}
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			break
		} else if event.Type == "" {
			continue
		}

		if event.Object.Status.Status != "" && event.Object.Status.Status != "OK" {
			continue
		}

		k8sPolicy := tp.K8sKubeArmorAuditPolicy{}
		if err := kl.Clone(event.Object, &k8sPolicy); err != nil {
			dm.LogFeeder.Printf("Failed to clone spec for Audit Policy (%s/%s). This event will be lost",
				strings.ToLower(event.Type), event.Object.Metadata.Name)
			continue
		}

		dm.K8sAuditPoliciesLock.Lock()

		if event.Type == "ADDED" {
			if !kl.ContainsElement(dm.K8sAuditPolicies, k8sPolicy) {
				dm.K8sAuditPolicies = append(dm.K8sAuditPolicies, k8sPolicy)
			}

		} else if event.Type == "DELETED" {
			for i, policy := range dm.K8sAuditPolicies {
				if policy.Metadata.Namespace == k8sPolicy.Metadata.Namespace &&
					policy.Metadata.Name == k8sPolicy.Metadata.Name {
					dm.K8sAuditPolicies = append(dm.K8sAuditPolicies[:i], dm.K8sAuditPolicies[i+1:]...)
					break
				}
			}

		} else if event.Type == "MODIFIED" {
			for i := 0; i < len(dm.K8sAuditPolicies); i++ {
				if dm.K8sAuditPolicies[i].Metadata.Namespace == k8sPolicy.Metadata.Namespace &&
					dm.K8sAuditPolicies[i].Metadata.Name == k8sPolicy.Metadata.Name {
					dm.K8sAuditPolicies[i] = k8sPolicy
					break
				}
			}
		}

		dm.K8sAuditPoliciesLock.Unlock()
		dm.LogFeeder.Printf("Detected an Audit Policy (%s/%s)", strings.ToLower(event.Type),
			k8sPolicy.Metadata.Name)
		dm.UpdateAuditPolicies()
	}
}

// WatchAuditPolicies Function
func (dm *KubeArmorDaemon) WatchAuditPolicies() {
	for {
		waitCustomResourceDefinition("kubearmorauditpolicies")
		if resp := K8s.WatchK8sAuditPolicies(); resp != nil {
			dm.decodeAuditPolicy(json.NewDecoder(resp.Body))
			if err := resp.Body.Close(); err != nil {
				kg.Err(err.Error())
			}
		}
	}
}

func (dm *KubeArmorDaemon) decodeKubeArmorMacro(decoder *json.Decoder) {
	for {
		event := tp.K8sKubeArmorMacroEvent{}
		if err := decoder.Decode(&event); err == io.EOF {
			break
		} else if err != nil {
			break
		} else if event.Type == "" {
			continue
		}

		if event.Object.Status.Status != "" && event.Object.Status.Status != "OK" {
			continue
		}

		k8sMacro := tp.K8sKubeArmorMacro{}
		if err := kl.Clone(event.Object, &k8sMacro); err != nil {
			dm.LogFeeder.Printf("Failed to clone spec for K8sMacro (%s/%s). This event will be lost",
				strings.ToLower(event.Type), event.Object.Metadata.Name)
			continue
		}

		dm.K8sMacrosLock.Lock()

		if event.Type == "ADDED" {
			if !kl.ContainsElement(dm.K8sMacros, k8sMacro) {
				dm.K8sMacros = append(dm.K8sMacros, k8sMacro)
			}

		} else if event.Type == "MODIFIED" {
			for i, macro := range dm.K8sMacros {
				if macro.Metadata.Namespace == k8sMacro.Metadata.Namespace &&
					macro.Metadata.Name == k8sMacro.Metadata.Name {
					dm.K8sMacros[i] = k8sMacro
					break
				}
			}

		} else if event.Type == "DELETED" {
			for i, macro := range dm.K8sMacros {
				if macro.Metadata.Namespace == k8sMacro.Metadata.Namespace &&
					macro.Metadata.Name == k8sMacro.Metadata.Name {
					dm.K8sMacros = append(dm.K8sMacros[:i], dm.K8sMacros[i+1:]...)
					break
				}
			}
		}

		dm.K8sMacrosLock.Unlock()

		dm.LogFeeder.Printf("Detected a Macro (%s/%s)", strings.ToLower(event.Type), event.Object.Metadata.Name)

		dm.UpdateAuditPolicies()
	}
}

// WatchKubeArmorMacro Function
func (dm *KubeArmorDaemon) WatchKubeArmorMacro() {
	for {
		waitCustomResourceDefinition("kubearmormacros")
		if resp := K8s.WatchK8sKubearmorMacro(); resp != nil {
			dm.decodeKubeArmorMacro(json.NewDecoder(resp.Body))
			if err := resp.Body.Close(); err != nil {
				kg.Err(err.Error())
			}
		}
	}
}
