// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"encoding/json"
	"io"
	"io/ioutil"
	"sort"
	"strings"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ================= //
// == Node Update == //
// ================= //

// HandleNodeAnnotations Handle Node Annotations i.e, set host visibility based on annotations, enable/disable policy
func (dm *KubeArmorDaemon) HandleNodeAnnotations(node *tp.Node) {
	if _, ok := node.Annotations["kubearmor-policy"]; ok {
		if node.Annotations["kubearmor-policy"] != "enabled" && node.Annotations["kubearmor-policy"] != "disabled" && node.Annotations["kubearmor-policy"] != "audited" {
			node.Annotations["kubearmor-policy"] = "enabled"
		}
	} else {
		node.Annotations["kubearmor-policy"] = "enabled"
	}

	if lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm"); err == nil {
		if !strings.Contains(string(lsm), "apparmor") && !strings.Contains(string(lsm), "selinux") {
			// exception: neither AppArmor nor SELinux
			if node.Annotations["kubearmor-policy"] == "enabled" {
				node.Annotations["kubearmor-policy"] = "audited"
			}
		}
	}

	if node.Annotations["kubearmor-policy"] == "enabled" {
		node.PolicyEnabled = tp.KubeArmorPolicyEnabled
	} else if node.Annotations["kubearmor-policy"] == "audited" || node.Annotations["kubearmor-policy"] == "patched" {
		node.PolicyEnabled = tp.KubeArmorPolicyAudited
	} else {
		node.PolicyEnabled = tp.KubeArmorPolicyDisabled
	}

	if _, ok := node.Annotations["kubearmor-visibility"]; !ok {
		node.Annotations["kubearmor-visibility"] = cfg.GlobalCfg.HostVisibility
	}

	for _, visibility := range strings.Split(node.Annotations["kubearmor-visibility"], ",") {
		if visibility == "process" {
			node.ProcessVisibilityEnabled = true
		} else if visibility == "file" {
			node.FileVisibilityEnabled = true
		} else if visibility == "network" {
			node.NetworkVisibilityEnabled = true
		} else if visibility == "capabilities" {
			node.CapabilitiesVisibilityEnabled = true
		}
	}
}

// WatchK8sNodes Function
func (dm *KubeArmorDaemon) WatchK8sNodes() {

	if nodeWatcher := K8s.WatchK8sNodes(); nodeWatcher != nil {
		return
	}

	go func() {
		for event := range nodeWatcher.ResultChan() {

			// Kubearmor uses hostname to get the corresponding node information, but there are exceptions.
			// For example, the node name on EKS can be of the format <hostname>.<region>.compute.internal
			nodeName := strings.Split(event.Object.GetObjectKind().GroupVersionKind().String(), ".")
			if nodeName[0] != cfg.GlobalCfg.Host {
				continue
			}

			node := tp.Node{}

			for _, address := range event.Object.(*corev1.Node).Status.Addresses {
				if address.Type == "InternalIP" {
					node.NodeIP = address.Address
					break
				}
			}

			node.Annotations = map[string]string{}
			node.Labels = map[string]string{}
			node.Identities = []string{}

			// update annotations
			for k, v := range event.Object.(*corev1.Node).ObjectMeta.Annotations {
				node.Annotations[k] = v
			}

			// update labels and identities
			for k, v := range event.Object.(*corev1.Node).ObjectMeta.Labels {
				node.Labels[k] = v
				node.Identities = append(node.Identities, k+"="+v)
			}

			sort.Slice(node.Identities, func(i, j int) bool {
				return node.Identities[i] < node.Identities[j]
			})

			// node info
			node.Architecture = event.Object.(*corev1.Node).Status.NodeInfo.Architecture
			node.OperatingSystem = event.Object.(*corev1.Node).Status.NodeInfo.OperatingSystem
			node.OSImage = event.Object.(*corev1.Node).Status.NodeInfo.OSImage
			node.KernelVersion = event.Object.(*corev1.Node).Status.NodeInfo.KernelVersion
			node.KubeletVersion = event.Object.(*corev1.Node).Status.NodeInfo.KubeletVersion

			// container runtime
			node.ContainerRuntimeVersion = event.Object.(*corev1.Node).Status.NodeInfo.ContainerRuntimeVersion

			dm.HandleNodeAnnotations(&node)

			dm.Node = node
		}
	}()
	time.Sleep(time.Second * 1)
}

// ================ //
// == Pod Update == //
// ================ //

// UpdateEndPointWithPod Function
func (dm *KubeArmorDaemon) UpdateEndPointWithPod(action string, pod tp.K8sPod) {
	if action == "ADDED" {
		// create a new endpoint
		newPoint := tp.EndPoint{}

		newPoint.NamespaceName = pod.Metadata["namespaceName"]
		newPoint.EndPointName = pod.Metadata["podName"]

		newPoint.Labels = map[string]string{}
		newPoint.Identities = []string{"namespaceName=" + pod.Metadata["namespaceName"]}

		// update labels and identities
		for k, v := range pod.Labels {
			newPoint.Labels[k] = v
			newPoint.Identities = append(newPoint.Identities, k+"="+v)
		}

		sort.Slice(newPoint.Identities, func(i, j int) bool {
			return newPoint.Identities[i] < newPoint.Identities[j]
		})

		// update policy flag
		if pod.Annotations["kubearmor-policy"] == "enabled" {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
		} else if pod.Annotations["kubearmor-policy"] == "audited" || pod.Annotations["kubearmor-policy"] == "patched" {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
		} else {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyDisabled
		}

		// parse annotations and update visibility flags
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

		newPoint.Containers = []string{}
		newPoint.AppArmorProfiles = []string{}
		newPoint.SELinuxProfiles = []string{}

		// update containers
		for k := range pod.Containers {
			newPoint.Containers = append(newPoint.Containers, k)
		}

		// update containers and apparmors
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

			if !kl.ContainsElement(newPoint.AppArmorProfiles, container.AppArmorProfile) {
				newPoint.AppArmorProfiles = append(newPoint.AppArmorProfiles, container.AppArmorProfile)
			}

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		// update selinux profile names to the endpoint
		for k, v := range pod.Annotations {
			if strings.HasPrefix(k, "kubearmor-selinux") {
				newPoint.SELinuxProfiles = append(newPoint.SELinuxProfiles, v)
			}
		}

		// update security policies with the identities
		newPoint.SecurityPolicies = dm.GetSecurityPolicies(newPoint.Identities)

		dm.EndPointsLock.Lock()

		// add the endpoint into the endpoint list
		dm.EndPoints = append(dm.EndPoints, newPoint)

		if cfg.GlobalCfg.Policy {
			// update security policies
			dm.Logger.UpdateSecurityPolicies(action, newPoint)

			if dm.RuntimeEnforcer != nil {
				if newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(newPoint)
				}
			}
		}

		dm.EndPointsLock.Unlock()

	} else if action == "MODIFIED" {
		newEndPoint := tp.EndPoint{}

		dm.EndPointsLock.Lock()
		for _, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				newEndPoint = endPoint
			}
		}
		dm.EndPointsLock.Unlock()

		newEndPoint.Labels = map[string]string{}
		newEndPoint.Identities = []string{"namespaceName=" + pod.Metadata["namespaceName"]}

		// update labels and identities
		for k, v := range pod.Labels {
			newEndPoint.Labels[k] = v
			newEndPoint.Identities = append(newEndPoint.Identities, k+"="+v)
		}

		sort.Slice(newEndPoint.Identities, func(i, j int) bool {
			return newEndPoint.Identities[i] < newEndPoint.Identities[j]
		})

		// update policy flag
		if pod.Annotations["kubearmor-policy"] == "enabled" {
			newEndPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
		} else if pod.Annotations["kubearmor-policy"] == "audited" || pod.Annotations["kubearmor-policy"] == "patched" {
			newEndPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
		} else {
			newEndPoint.PolicyEnabled = tp.KubeArmorPolicyDisabled
		}

		newEndPoint.ProcessVisibilityEnabled = false
		newEndPoint.FileVisibilityEnabled = false
		newEndPoint.NetworkVisibilityEnabled = false
		newEndPoint.CapabilitiesVisibilityEnabled = false

		// parse annotations and update visibility flags
		for _, visibility := range strings.Split(pod.Annotations["kubearmor-visibility"], ",") {
			if visibility == "process" {
				newEndPoint.ProcessVisibilityEnabled = true
			} else if visibility == "file" {
				newEndPoint.FileVisibilityEnabled = true
			} else if visibility == "network" {
				newEndPoint.NetworkVisibilityEnabled = true
			} else if visibility == "capabilities" {
				newEndPoint.CapabilitiesVisibilityEnabled = true
			}
		}

		newEndPoint.Containers = []string{}
		newEndPoint.AppArmorProfiles = []string{}
		newEndPoint.SELinuxProfiles = []string{}

		// update containers
		for k := range pod.Containers {
			newEndPoint.Containers = append(newEndPoint.Containers, k)
		}

		// update containers and apparmors
		dm.ContainersLock.Lock()
		for _, containerID := range newEndPoint.Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = newEndPoint.NamespaceName
			container.EndPointName = newEndPoint.EndPointName
			container.ContainerName = pod.Containers[containerID]

			container.PolicyEnabled = newEndPoint.PolicyEnabled

			container.ProcessVisibilityEnabled = newEndPoint.ProcessVisibilityEnabled
			container.FileVisibilityEnabled = newEndPoint.FileVisibilityEnabled
			container.NetworkVisibilityEnabled = newEndPoint.NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = newEndPoint.CapabilitiesVisibilityEnabled

			if !kl.ContainsElement(newEndPoint.AppArmorProfiles, container.AppArmorProfile) {
				newEndPoint.AppArmorProfiles = append(newEndPoint.AppArmorProfiles, container.AppArmorProfile)
			}

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		// update selinux profile names to the endpoint
		for k, v := range pod.Annotations {
			if strings.HasPrefix(k, "kubearmor-selinux") {
				newEndPoint.SELinuxProfiles = append(newEndPoint.SELinuxProfiles, v)
			}
		}

		// get security policies according to the updated identities
		newEndPoint.SecurityPolicies = dm.GetSecurityPolicies(newEndPoint.Identities)

		dm.EndPointsLock.Lock()

		for idx, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				dm.EndPoints[idx] = newEndPoint
			}
		}

		if cfg.GlobalCfg.Policy {
			// update security policies
			dm.Logger.UpdateSecurityPolicies(action, newEndPoint)

			if dm.RuntimeEnforcer != nil {
				if newEndPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(newEndPoint)
				}
			}
		}

		dm.EndPointsLock.Unlock()

	} else { // DELETED
		dm.EndPointsLock.Lock()
		for idx, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				// remove endpoint
				dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)
				break
			}
		}
		dm.EndPointsLock.Unlock()
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

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
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

				// == Policy == //

				if _, ok := pod.Annotations["kubearmor-policy"]; ok {
					if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" && pod.Annotations["kubearmor-policy"] != "audited" {
						pod.Annotations["kubearmor-policy"] = "enabled"
					}
				} else {
					pod.Annotations["kubearmor-policy"] = "enabled"
				}

				// == LSM == //

				if dm.RuntimeEnforcer == nil {
					// exception: no LSM
					if pod.Annotations["kubearmor-policy"] == "enabled" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				} else if lsm, err := ioutil.ReadFile("/sys/kernel/security/lsm"); err == nil {
					if !strings.Contains(string(lsm), "apparmor") && !strings.Contains(string(lsm), "selinux") {
						// exception: neither AppArmor nor SELinux
						if pod.Annotations["kubearmor-policy"] == "enabled" {
							pod.Annotations["kubearmor-policy"] = "audited"
						}
					}
				}

				// == Exception == //

				// exception: kubernetes app
				if pod.Metadata["namespaceName"] == "kube-system" {
					if _, ok := pod.Labels["k8s-app"]; ok {
						pod.Annotations["kubearmor-policy"] = "audited"
					}

					if value, ok := pod.Labels["component"]; ok {
						if value == "etcd" || value == "kube-apiserver" || value == "kube-controller-manager" || value == "kube-scheduler" {
							pod.Annotations["kubearmor-policy"] = "audited"
						}
					}
				}

				// exception: cilium-operator
				if _, ok := pod.Labels["io.cilium/app"]; ok {
					pod.Annotations["kubearmor-policy"] = "audited"
				}

				// exception: kubearmor
				if _, ok := pod.Labels["kubearmor-app"]; ok {
					pod.Annotations["kubearmor-policy"] = "audited"
				}

				// == Visibility == //

				if _, ok := pod.Annotations["kubearmor-visibility"]; !ok {
					pod.Annotations["kubearmor-visibility"] = cfg.GlobalCfg.Visibility
				}

				// == Skip if already patched == //

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

				if dm.RuntimeEnforcer != nil && dm.RuntimeEnforcer.EnforcerType == "AppArmor" {
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

					if event.Type == "ADDED" {
						// update apparmor profiles
						dm.RuntimeEnforcer.UpdateAppArmorProfiles(pod.Metadata["podName"], "ADDED", appArmorAnnotations)

						if updateAppArmor && pod.Annotations["kubearmor-policy"] == "enabled" {
							if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
								// patch the deployment with apparmor annotations
								if err := K8s.PatchDeploymentWithAppArmorAnnotations(pod.Metadata["namespaceName"], deploymentName, appArmorAnnotations); err != nil {
									dm.Logger.Errf("Failed to update AppArmor Annotations (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
								} else {
									dm.Logger.Printf("Patched AppArmor Annotations (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
								}
								pod.Annotations["kubearmor-policy"] = "patched"
							}
						}
					} else if event.Type == "MODIFIED" {
						for _, k8spod := range dm.K8sPods {
							if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
								prevPolicyEnabled := "disabled"

								if val, ok := k8spod.Annotations["kubearmor-policy"]; ok {
									prevPolicyEnabled = val
								}

								if updateAppArmor && prevPolicyEnabled != "enabled" && pod.Annotations["kubearmor-policy"] == "enabled" {
									if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
										// patch the deployment with apparmor annotations
										if err := K8s.PatchDeploymentWithAppArmorAnnotations(pod.Metadata["namespaceName"], deploymentName, appArmorAnnotations); err != nil {
											dm.Logger.Errf("Failed to update AppArmor Annotations (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
										} else {
											dm.Logger.Printf("Patched AppArmor Annotations (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
										}
										pod.Annotations["kubearmor-policy"] = "patched"
									}
								}

								break
							}
						}
					} else if event.Type == "DELETED" {
						// update apparmor profiles
						dm.RuntimeEnforcer.UpdateAppArmorProfiles(pod.Metadata["podName"], "DELETED", appArmorAnnotations)
					}
				}

				// == SELinux == //

				if dm.RuntimeEnforcer != nil && dm.RuntimeEnforcer.EnforcerType == "SELinux" {
					seLinuxAnnotations := map[string]string{}
					updateSELinux := false

					for k, v := range pod.Annotations {
						if strings.HasPrefix(k, "kubearmor-selinux") {
							containerName := strings.Split(k, "/")[1]
							seLinuxAnnotations[containerName] = v
						}
					}

					for _, container := range event.Object.Spec.Containers {
						if _, ok := seLinuxAnnotations[container.Name]; !ok {
							seLinuxAnnotations[container.Name] = "kubearmor-" + pod.Metadata["namespaceName"] + "-" + container.Name
							updateSELinux = true
						}
					}

					if event.Type == "ADDED" {
						// update selinux profiles
						dm.RuntimeEnforcer.UpdateSELinuxProfiles(pod.Metadata["podName"], "ADDED", seLinuxAnnotations)

						if updateSELinux && pod.Annotations["kubearmor-policy"] == "enabled" {
							if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
								// patch the deployment with selinux annotations
								if err := K8s.PatchDeploymentWithSELinuxAnnotations(pod.Metadata["namespaceName"], deploymentName, seLinuxAnnotations); err != nil {
									dm.Logger.Errf("Failed to update SELinux Annotations for KubeArmor (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
								} else {
									dm.Logger.Printf("Patched SELinux Annotations for KubeArmor (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
								}
								pod.Annotations["kubearmor-policy"] = "patched"
							}
						}
					} else if event.Type == "MODIFIED" {
						for _, k8spod := range dm.K8sPods {
							if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
								prevPolicyEnabled := "disabled"

								if val, ok := k8spod.Annotations["kubearmor-policy"]; ok {
									prevPolicyEnabled = val
								}

								if updateSELinux && prevPolicyEnabled != "enabled" && pod.Annotations["kubearmor-policy"] == "enabled" {
									if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
										// patch the deployment with selinux annotations
										if err := K8s.PatchDeploymentWithSELinuxAnnotations(pod.Metadata["namespaceName"], deploymentName, seLinuxAnnotations); err != nil {
											dm.Logger.Errf("Failed to update SELinux Annotations for KubeArmor (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
										} else {
											dm.Logger.Printf("Patched SELinux Annotations for KubeArmor (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
										}
										pod.Annotations["kubearmor-policy"] = "patched"
									}
								}

								break
							}
						}
					} else if event.Type == "DELETED" {
						// update selinux profiles
						dm.RuntimeEnforcer.UpdateSELinuxProfiles(pod.Metadata["podName"], "DELETED", seLinuxAnnotations)
					}
				}

				dm.K8sPodsLock.Lock()

				if event.Type == "ADDED" {
					new := true
					for _, k8spod := range dm.K8sPods {
						if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
							new = false
							break
						}
					}
					if new {
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
				}

				dm.K8sPodsLock.Unlock()

				if pod.Annotations["kubearmor-policy"] == "patched" {
					dm.Logger.Printf("Detected a Pod (patched/%s/%s)", pod.Metadata["namespaceName"], pod.Metadata["podName"])
				} else {
					dm.Logger.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event.Type), pod.Metadata["namespaceName"], pod.Metadata["podName"])
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
				dm.Logger.Errf("Failed to clone a policy (%s)", err.Error())
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
				new := true
				for _, policy := range endPoint.SecurityPolicies {
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						new = false
						break
					}
				}
				if new {
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
					if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
						dm.EndPoints[idx].SecurityPolicies = append(dm.EndPoints[idx].SecurityPolicies[:idxP], dm.EndPoints[idx].SecurityPolicies[idxP+1:]...)
						break
					}
				}
			}

			if cfg.GlobalCfg.Policy {
				// update security policies
				dm.Logger.UpdateSecurityPolicies("UPDATED", dm.EndPoints[idx])

				if dm.RuntimeEnforcer != nil {
					if dm.EndPoints[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
						// enforce security policies
						dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.EndPoints[idx])
					}
				}
			}
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

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				// create a security policy

				secPolicy := tp.SecurityPolicy{}

				secPolicy.Metadata = map[string]string{}
				secPolicy.Metadata["namespaceName"] = event.Object.Metadata.Namespace
				secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

				if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
					dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
					continue
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

				for k, v := range secPolicy.Spec.Selector.MatchLabels {
					secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
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

				// update a security policy into the policy list

				dm.SecurityPoliciesLock.Lock()

				if event.Type == "ADDED" {
					new := true
					for _, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							new = false
							break
						}
					}
					if new {
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
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
							break
						}
					}
				}

				dm.SecurityPoliciesLock.Unlock()

				dm.Logger.Printf("Detected a Security Policy (%s/%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

				// apply security policies to pods
				dm.UpdateSecurityPolicy(event.Type, secPolicy)
			}
		}
	}
}

// ================================= //
// == Host Security Policy Update == //
// ================================= //

// UpdateHostSecurityPolicies Function
func (dm *KubeArmorDaemon) UpdateHostSecurityPolicies() {
	dm.HostSecurityPoliciesLock.Lock()
	defer dm.HostSecurityPoliciesLock.Unlock()

	secPolicies := []tp.HostSecurityPolicy{}

	for _, policy := range dm.HostSecurityPolicies {
		if kl.IsK8sEnv() {
			if kl.MatchIdentities(policy.Spec.NodeSelector.Identities, dm.Node.Identities) {
				secPolicies = append(secPolicies, policy)
			}
		} else { // KubeArmorVM
			secPolicies = append(secPolicies, policy)
		}
	}

	if cfg.GlobalCfg.HostPolicy {
		// update host security policies
		dm.Logger.UpdateHostSecurityPolicies("UPDATED", secPolicies)

		if dm.RuntimeEnforcer != nil {
			if dm.Node.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				// enforce host security policies
				dm.RuntimeEnforcer.UpdateHostSecurityPolicies(secPolicies)
			}
		}
	}
}

// ParseAndUpdateHostSecurityPolicy Function
func (dm *KubeArmorDaemon) ParseAndUpdateHostSecurityPolicy(event tp.K8sKubeArmorHostPolicyEvent) {
	// create a host security policy

	secPolicy := tp.HostSecurityPolicy{}

	secPolicy.Metadata = map[string]string{}
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

	secPolicy.Spec.NodeSelector.Identities = []string{}

	for k, v := range secPolicy.Spec.NodeSelector.MatchLabels {
		secPolicy.Spec.NodeSelector.Identities = append(secPolicy.Spec.NodeSelector.Identities, k+"="+v)
	}

	sort.Slice(secPolicy.Spec.NodeSelector.Identities, func(i, j int) bool {
		return secPolicy.Spec.NodeSelector.Identities[i] < secPolicy.Spec.NodeSelector.Identities[j]
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

	dm.HostSecurityPoliciesLock.Lock()

	if event.Type == "ADDED" {
		new := true
		for idx, policy := range dm.HostSecurityPolicies {
			if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				dm.HostSecurityPolicies[idx] = secPolicy
				event.Type = "MODIFIED"
				new = false
				break
			}
		}
		if new {
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
			if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				dm.HostSecurityPolicies = append(dm.HostSecurityPolicies[:idx], dm.HostSecurityPolicies[idx+1:]...)
				break
			}
		}
	}

	dm.HostSecurityPoliciesLock.Unlock()

	dm.Logger.Printf("Detected a Host Security Policy (%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["policyName"])

	// apply security policies to a host
	dm.UpdateHostSecurityPolicies()
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

				if event.Type != "ADDED" && event.Type != "MODIFIED" && event.Type != "DELETED" {
					continue
				}

				dm.ParseAndUpdateHostSecurityPolicy(event)
			}
		}
	}
}
