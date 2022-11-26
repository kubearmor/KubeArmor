// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

// ================= //
// == Node Update == //
// ================= //

// HandleNodeAnnotations Handle Node Annotations i.e, set host visibility based on annotations, enable/disable policy
func (dm *KubeArmorDaemon) HandleNodeAnnotations(node *tp.Node) {
	if _, ok := node.Annotations["kubearmor-policy"]; !ok {
		node.Annotations["kubearmor-policy"] = "enabled"
	}

	if node.Annotations["kubearmor-policy"] != "enabled" && node.Annotations["kubearmor-policy"] != "disabled" && node.Annotations["kubearmor-policy"] != "audited" {
		node.Annotations["kubearmor-policy"] = "enabled"
	}

	if lsm, err := os.ReadFile("/sys/kernel/security/lsm"); err == nil {
		if !strings.Contains(string(lsm), "apparmor") && !strings.Contains(string(lsm), "selinux") {
			// exception: neither AppArmor nor SELinux
			if node.Annotations["kubearmor-policy"] == "enabled" {
				node.Annotations["kubearmor-policy"] = "audited"
			}
		}

		if kl.IsInK8sCluster() && strings.Contains(string(lsm), "selinux") {
			// exception: KubeArmor in a daemonset even though SELinux is enabled
			if node.Annotations["kubearmor-policy"] == "enabled" {
				node.Annotations["kubearmor-policy"] = "audited"
			}
		}
	}

	if node.Annotations["kubearmor-policy"] == "enabled" {
		node.PolicyEnabled = tp.KubeArmorPolicyEnabled
	} else if node.Annotations["kubearmor-policy"] == "audited" {
		node.PolicyEnabled = tp.KubeArmorPolicyAudited
	} else { // disabled
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

func matchHost(hostName string) bool {
	envName := os.Getenv("KUBEARMOR_NODENAME")
	if envName != "" {
		return envName == hostName
	}
	nodeName := strings.Split(hostName, ".")[0]
	return nodeName == cfg.GlobalCfg.Host
}

// WatchK8sNodes Function
func (dm *KubeArmorDaemon) WatchK8sNodes() {
	kg.Printf("GlobalCfg.Host=%s, KUBEARMOR_NODENAME=%s", cfg.GlobalCfg.Host, os.Getenv("KUBEARMOR_NODENAME"))
	for {
		if resp := K8s.WatchK8sNodes(); resp != nil {
			defer resp.Body.Close()

			decoder := json.NewDecoder(resp.Body)
			for {
				event := tp.K8sNodeEvent{}
				if err := decoder.Decode(&event); err == io.EOF {
					break
				} else if err != nil {
					break
				}

				// Kubearmor uses hostname to get the corresponding node information, but there are exceptions.
				// For example, the node name on EKS can be of the format <hostname>.<region>.compute.internal
				/* Keeping this past code for near-future ref purpose. Jun-13-2022
				nodeName := strings.Split(event.Object.ObjectMeta.Name, ".")[0]
				if nodeName != cfg.GlobalCfg.Host {
					continue
				}
				*/
				if !matchHost(event.Object.ObjectMeta.Name) {
					continue
				}

				node := tp.Node{}

				node.ClusterName = cfg.GlobalCfg.Cluster
				node.NodeName = cfg.GlobalCfg.Host

				for _, address := range event.Object.Status.Addresses {
					if address.Type == "InternalIP" {
						node.NodeIP = address.Address
						break
					}
				}

				node.Annotations = map[string]string{}
				node.Labels = map[string]string{}
				node.Identities = []string{}

				// update annotations
				for k, v := range event.Object.ObjectMeta.Annotations {
					node.Annotations[k] = v
				}

				// update labels and identities
				for k, v := range event.Object.ObjectMeta.Labels {
					node.Labels[k] = v
					node.Identities = append(node.Identities, k+"="+v)
				}

				sort.Slice(node.Identities, func(i, j int) bool {
					return node.Identities[i] < node.Identities[j]
				})

				// node info
				node.Architecture = event.Object.Status.NodeInfo.Architecture
				node.OperatingSystem = event.Object.Status.NodeInfo.OperatingSystem
				node.OSImage = event.Object.Status.NodeInfo.OSImage
				node.KernelVersion = event.Object.Status.NodeInfo.KernelVersion
				node.KubeletVersion = event.Object.Status.NodeInfo.KubeletVersion

				// container runtime
				node.ContainerRuntimeVersion = event.Object.Status.NodeInfo.ContainerRuntimeVersion

				dm.HandleNodeAnnotations(&node)

				dm.Node = node
			}
		} else {
			time.Sleep(time.Second * 1)
		}
	}
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
		} else if pod.Annotations["kubearmor-policy"] == "audited" {
			newPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
		} else { // disabled
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

		// update containers
		for k := range pod.Containers {
			newPoint.Containers = append(newPoint.Containers, k)
		}

		containersAppArmorProfiles := map[string]string{}

		// update containers and apparmors
		dm.ContainersLock.Lock()
		for _, containerID := range newPoint.Containers {
			container := dm.Containers[containerID]

			container.NamespaceName = newPoint.NamespaceName
			container.EndPointName = newPoint.EndPointName

			labels := []string{}
			for k, v := range newPoint.Labels {
				labels = append(labels, k+"="+v)
			}
			container.Labels = strings.Join(labels, ",")

			container.ContainerName = pod.Containers[containerID]
			container.ContainerImage = pod.ContainerImages[containerID]

			container.PolicyEnabled = newPoint.PolicyEnabled

			container.ProcessVisibilityEnabled = newPoint.ProcessVisibilityEnabled
			container.FileVisibilityEnabled = newPoint.FileVisibilityEnabled
			container.NetworkVisibilityEnabled = newPoint.NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = newPoint.CapabilitiesVisibilityEnabled

			containersAppArmorProfiles[containerID] = container.AppArmorProfile
			if !kl.ContainsElement(newPoint.AppArmorProfiles, container.AppArmorProfile) {
				newPoint.AppArmorProfiles = append(newPoint.AppArmorProfiles, container.AppArmorProfile)
			}

			dm.Containers[containerID] = container
		}
		dm.ContainersLock.Unlock()

		dm.DefaultPosturesLock.Lock()
		if val, ok := dm.DefaultPostures[newPoint.NamespaceName]; ok {
			newPoint.DefaultPosture = val
		} else {
			globalDefaultPosture := tp.DefaultPosture{
				FileAction:         cfg.GlobalCfg.DefaultFilePosture,
				NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
				CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
			}
			dm.DefaultPostures[newPoint.NamespaceName] = globalDefaultPosture
			newPoint.DefaultPosture = globalDefaultPosture
		}
		dm.DefaultPosturesLock.Unlock()

		// update security policies with the identities
		newPoint.SecurityPolicies = dm.GetSecurityPolicies(newPoint.Identities)

		endpoints := []tp.EndPoint{}
		for k, v := range pod.Containers {
			endpoint := newPoint
			endpoint.Containers = []string{}
			endpoint.AppArmorProfiles = []string{}
			endpoint.SecurityPolicies = []tp.SecurityPolicy{}
			endpoint.AppArmorProfiles = append(endpoint.AppArmorProfiles, containersAppArmorProfiles[k])
			endpoint.Containers = append(endpoint.Containers, k)
			endpoint.ContainerName = v

			for _, secPolicy := range newPoint.SecurityPolicies {
				if len(secPolicy.Spec.Selector.Containers) == 0 || kl.ContainsElement(secPolicy.Spec.Selector.Containers, v) {
					endpoint.SecurityPolicies = append(endpoint.SecurityPolicies, secPolicy)
				}
			}

			endpoints = append(endpoints, endpoint)
		}

		dm.EndPointsLock.Lock()

		// add the endpoint into the endpoint list
		dm.EndPoints = append(dm.EndPoints, endpoints...)

		if cfg.GlobalCfg.Policy {
			// update security policies
			for _, endpoint := range endpoints {
				dm.Logger.UpdateSecurityPolicies(action, endpoint)
				if dm.RuntimeEnforcer != nil && newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
				}
			}
		}

		dm.EndPointsLock.Unlock()

	} else if action == "MODIFIED" {
		newEndPoint := tp.EndPoint{}
		endpoints := []tp.EndPoint{}

		dm.EndPointsLock.Lock()
		for _, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				endpoints = append(endpoints, endPoint)
			}
		}
		dm.EndPointsLock.Unlock()
		if len(endpoints) == 0 {
			// No endpoints were added as containers ID have been just added
			// Same logic as ADDED
			dm.UpdateEndPointWithPod("ADDED", pod)

		} else {
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
			} else if pod.Annotations["kubearmor-policy"] == "audited" {
				newEndPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
			} else { // disabled
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

			containersAppArmorProfiles := map[string]string{}

			// update containers and apparmors
			dm.ContainersLock.Lock()
			for _, containerID := range newEndPoint.Containers {
				container := dm.Containers[containerID]

				container.NamespaceName = newEndPoint.NamespaceName
				container.EndPointName = newEndPoint.EndPointName

				labels := []string{}
				for k, v := range newEndPoint.Labels {
					labels = append(labels, k+"="+v)
				}
				container.Labels = strings.Join(labels, ",")

				container.ContainerName = pod.Containers[containerID]
				container.ContainerImage = pod.ContainerImages[containerID]

				container.PolicyEnabled = newEndPoint.PolicyEnabled

				container.ProcessVisibilityEnabled = newEndPoint.ProcessVisibilityEnabled
				container.FileVisibilityEnabled = newEndPoint.FileVisibilityEnabled
				container.NetworkVisibilityEnabled = newEndPoint.NetworkVisibilityEnabled
				container.CapabilitiesVisibilityEnabled = newEndPoint.CapabilitiesVisibilityEnabled

				containersAppArmorProfiles[containerID] = container.AppArmorProfile
				if !kl.ContainsElement(newEndPoint.AppArmorProfiles, container.AppArmorProfile) {
					newEndPoint.AppArmorProfiles = append(newEndPoint.AppArmorProfiles, container.AppArmorProfile)
				}

				dm.Containers[containerID] = container
			}
			dm.ContainersLock.Unlock()

			dm.DefaultPosturesLock.Lock()
			if val, ok := dm.DefaultPostures[newEndPoint.NamespaceName]; ok {
				newEndPoint.DefaultPosture = val
			} else {
				globalDefaultPosture := tp.DefaultPosture{
					FileAction:         cfg.GlobalCfg.DefaultFilePosture,
					NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
					CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
				}
				dm.DefaultPostures[newEndPoint.NamespaceName] = globalDefaultPosture
				newEndPoint.DefaultPosture = globalDefaultPosture
			}
			dm.DefaultPosturesLock.Unlock()

			// get security policies according to the updated identities
			newEndPoint.SecurityPolicies = dm.GetSecurityPolicies(newEndPoint.Identities)

			newendpoints := []tp.EndPoint{}
			for k, v := range pod.Containers {
				endpoint := newEndPoint
				endpoint.Containers = []string{}
				endpoint.AppArmorProfiles = []string{}
				endpoint.SecurityPolicies = []tp.SecurityPolicy{}
				endpoint.AppArmorProfiles = append(endpoint.AppArmorProfiles, containersAppArmorProfiles[k])
				endpoint.Containers = append(endpoint.Containers, k)
				endpoint.ContainerName = v

				for _, secPolicy := range newEndPoint.SecurityPolicies {
					if len(secPolicy.Spec.Selector.Containers) == 0 || kl.ContainsElement(secPolicy.Spec.Selector.Containers, v) {
						endpoint.SecurityPolicies = append(endpoint.SecurityPolicies, secPolicy)
					}
				}

				endpoints = append(newendpoints, endpoint)
			}

			dm.EndPointsLock.Lock()

			idx := 0
			nidx := 0
			for nidx < len(endpoints) && idx < len(dm.EndPoints) {
				if pod.Metadata["namespaceName"] == dm.EndPoints[idx].NamespaceName && pod.Metadata["podName"] == dm.EndPoints[idx].EndPointName && kl.ContainsElement(endpoints, dm.EndPoints[idx].ContainerName) {
					dm.EndPoints[idx] = endpoints[nidx]
					nidx++
				}
				idx++
			}

			for _, endpoint := range endpoints {
				if cfg.GlobalCfg.Policy {
					// update security policies
					dm.Logger.UpdateSecurityPolicies(action, endpoint)

					if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
						// enforce security policies
						dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
					}
				}
			}

			dm.EndPointsLock.Unlock()
		}

	} else { // DELETED
		dm.EndPointsLock.Lock()
		idx := 0
		endpointsLength := len(dm.EndPoints)
		for idx < endpointsLength {
			endpoint := dm.EndPoints[idx]
			if pod.Metadata["namespaceName"] == endpoint.NamespaceName && pod.Metadata["podName"] == endpoint.EndPointName {
				dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)
				endpointsLength--
				idx--
			}
			idx++
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
				containers := []string{}

				// need this for apparmor profile
				var podOwnerName string

				pod.Metadata = map[string]string{}
				pod.Metadata["namespaceName"] = event.Object.ObjectMeta.Namespace
				pod.Metadata["podName"] = event.Object.ObjectMeta.Name

				ownerRef := kl.GetControllingPodOwner(event.Object.ObjectMeta.OwnerReferences)
				if ownerRef != nil {
					podOwnerName = ownerRef.Name
					if ownerRef.Kind == "ReplicaSet" {
						deploymentName := K8s.GetDeploymentNameControllingReplicaSet(pod.Metadata["namespaceName"], podOwnerName)
						if deploymentName != "" {
							pod.Metadata["deploymentName"] = deploymentName
						}
						// if it belongs to a replicaset, we also remove the pod template hash
						podOwnerName = strings.TrimSuffix(podOwnerName, fmt.Sprintf("-%s", event.Object.ObjectMeta.Labels["pod-template-hash"]))
					}
				} else {
					// static pod
					podOwnerName = event.Object.ObjectMeta.Name
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
				pod.ContainerImages = map[string]string{}
				for _, container := range event.Object.Status.ContainerStatuses {
					if len(container.ContainerID) > 0 {
						if strings.HasPrefix(container.ContainerID, "docker://") {
							containerID := strings.TrimPrefix(container.ContainerID, "docker://")
							pod.Containers[containerID] = container.Name
							pod.ContainerImages[containerID] = container.Image + kl.GetSHA256ofImage(container.ImageID)
						} else if strings.HasPrefix(container.ContainerID, "containerd://") {
							containerID := strings.TrimPrefix(container.ContainerID, "containerd://")
							pod.Containers[containerID] = container.Name
							pod.ContainerImages[containerID] = container.Image + kl.GetSHA256ofImage(container.ImageID)
						} else if strings.HasPrefix(container.ContainerID, "cri-o://") {
							containerID := strings.TrimPrefix(container.ContainerID, "cri-o://")
							pod.Containers[containerID] = container.Name
							pod.ContainerImages[containerID] = container.Image + kl.GetSHA256ofImage(container.ImageID)
						}
					}
				}

				// == Policy == //

				if _, ok := pod.Annotations["kubearmor-policy"]; !ok {
					pod.Annotations["kubearmor-policy"] = "enabled"
				}

				if pod.Annotations["kubearmor-policy"] != "enabled" && pod.Annotations["kubearmor-policy"] != "disabled" && pod.Annotations["kubearmor-policy"] != "audited" {
					pod.Annotations["kubearmor-policy"] = "enabled"
				}

				// == LSM == //

				if dm.RuntimeEnforcer == nil {
					// exception: no LSM
					if pod.Annotations["kubearmor-policy"] == "enabled" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				} else if dm.RuntimeEnforcer != nil && dm.RuntimeEnforcer.EnforcerType == "SELinux" {
					// exception: no SELinux support for containers
					if pod.Annotations["kubearmor-policy"] == "enabled" {
						pod.Annotations["kubearmor-policy"] = "audited"
					}
				}

				// == Exception == //

				// exception: kubernetes app
				if pod.Metadata["namespaceName"] == "kube-system" {
					pod.Annotations["kubearmor-policy"] = "audited"
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

				// == AppArmor == //

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

				if dm.RuntimeEnforcer != nil && dm.RuntimeEnforcer.EnforcerType == "AppArmor" {
					appArmorAnnotations := map[string]string{}
					updateAppArmor := false

					if deploymentName, ok := pod.Metadata["deploymentName"]; ok {
						deploy, err := K8s.K8sClient.AppsV1().Deployments(pod.Metadata["namespaceName"]).Get(context.Background(), deploymentName, metav1.GetOptions{})
						if err == nil {
							for _, c := range deploy.Spec.Template.Spec.Containers {
								containers = append(containers, c.Name)
							}
						}
					}

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
						if _, ok := appArmorAnnotations[container.Name]; !ok && kl.ContainsElement(containers, container.Name) {
							appArmorAnnotations[container.Name] = "kubearmor-" + pod.Metadata["namespaceName"] + "-" + podOwnerName + "-" + container.Name
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
					continue
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
		if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) && (len(secPolicy.Spec.Selector.Containers) == 0 || kl.ContainsElement(secPolicy.Spec.Selector.Containers, endPoint.ContainerName)) {
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
					if k == "kubearmor.io/container.name" {
						if len(v) > 2 {
							containerArray := v[1 : len(v)-1]
							containers := strings.Split(containerArray, ",")
							for _, container := range containers {
								if len(container) > 0 {
									secPolicy.Spec.Selector.Containers = append(secPolicy.Spec.Selector.Containers, strings.TrimSpace(container))
								}

							}
						}
					} else {
						secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
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

				if len(secPolicy.Spec.Syscalls.MatchSyscalls) > 0 {
					for idx, syscall := range secPolicy.Spec.Syscalls.MatchSyscalls {
						if syscall.Severity == 0 {
							if secPolicy.Spec.Syscalls.Severity != 0 {
								secPolicy.Spec.Syscalls.MatchSyscalls[idx].Severity = secPolicy.Spec.Syscalls.Severity
							} else {
								secPolicy.Spec.Syscalls.MatchSyscalls[idx].Severity = secPolicy.Spec.Severity
							}
						}

						if len(syscall.Tags) == 0 {
							if len(secPolicy.Spec.Syscalls.Tags) > 0 {
								secPolicy.Spec.Syscalls.MatchSyscalls[idx].Tags = secPolicy.Spec.Syscalls.Tags
							} else {
								secPolicy.Spec.Syscalls.MatchSyscalls[idx].Tags = secPolicy.Spec.Tags
							}
						}

						if len(syscall.Message) == 0 {
							if len(secPolicy.Spec.Syscalls.Message) > 0 {
								secPolicy.Spec.Syscalls.MatchSyscalls[idx].Message = secPolicy.Spec.Syscalls.Message
							} else {
								secPolicy.Spec.Syscalls.MatchSyscalls[idx].Message = secPolicy.Spec.Message
							}
						}

					}
				}

				if len(secPolicy.Spec.Syscalls.MatchPaths) > 0 {
					for idx, syscall := range secPolicy.Spec.Syscalls.MatchPaths {
						if syscall.Severity == 0 {
							if secPolicy.Spec.Syscalls.Severity != 0 {
								secPolicy.Spec.Syscalls.MatchPaths[idx].Severity = secPolicy.Spec.Syscalls.Severity
							} else {
								secPolicy.Spec.Syscalls.MatchPaths[idx].Severity = secPolicy.Spec.Severity
							}
						}

						if len(syscall.Tags) == 0 {
							if len(secPolicy.Spec.Syscalls.Tags) > 0 {
								secPolicy.Spec.Syscalls.MatchPaths[idx].Tags = secPolicy.Spec.Syscalls.Tags
							} else {
								secPolicy.Spec.Syscalls.MatchPaths[idx].Tags = secPolicy.Spec.Tags
							}
						}

						if len(syscall.Message) == 0 {
							if len(secPolicy.Spec.Syscalls.Message) > 0 {
								secPolicy.Spec.Syscalls.MatchPaths[idx].Message = secPolicy.Spec.Syscalls.Message
							} else {
								secPolicy.Spec.Syscalls.MatchPaths[idx].Message = secPolicy.Spec.Message
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

// ====================================== //
// == Container Security Policy Update == //
// ====================================== //

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
		} else { // KubeArmorVM and KVMAgent
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

	if len(secPolicy.Spec.Syscalls.MatchSyscalls) > 0 {
		for idx, syscall := range secPolicy.Spec.Syscalls.MatchSyscalls {
			if syscall.Severity == 0 {
				if secPolicy.Spec.Syscalls.Severity != 0 {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Severity = secPolicy.Spec.Syscalls.Severity
				} else {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(syscall.Tags) == 0 {
				if len(secPolicy.Spec.Syscalls.Tags) > 0 {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Tags = secPolicy.Spec.Syscalls.Tags
				} else {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(syscall.Message) == 0 {
				if len(secPolicy.Spec.Syscalls.Message) > 0 {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Message = secPolicy.Spec.Syscalls.Message
				} else {
					secPolicy.Spec.Syscalls.MatchSyscalls[idx].Message = secPolicy.Spec.Message
				}
			}

		}
	}

	if len(secPolicy.Spec.Syscalls.MatchPaths) > 0 {
		for idx, syscall := range secPolicy.Spec.Syscalls.MatchPaths {
			if syscall.Severity == 0 {
				if secPolicy.Spec.Syscalls.Severity != 0 {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Severity = secPolicy.Spec.Syscalls.Severity
				} else {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(syscall.Tags) == 0 {
				if len(secPolicy.Spec.Syscalls.Tags) > 0 {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Tags = secPolicy.Spec.Syscalls.Tags
				} else {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(syscall.Message) == 0 {
				if len(secPolicy.Spec.Syscalls.Message) > 0 {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Message = secPolicy.Spec.Syscalls.Message
				} else {
					secPolicy.Spec.Syscalls.MatchPaths[idx].Message = secPolicy.Spec.Message
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

	if !cfg.GlobalCfg.K8sEnv && (cfg.GlobalCfg.KVMAgent || cfg.GlobalCfg.HostPolicy) {
		if event.Type == "ADDED" || event.Type == "MODIFIED" {
			// backup HostSecurityPolicy to file
			dm.backupKubeArmorHostPolicy(secPolicy)
		} else if event.Type == "DELETED" {
			dm.removeBackUpPolicy(secPolicy.Metadata["policyName"])
		}
	}
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

func (dm *KubeArmorDaemon) restoreKubeArmorHostPolicies() {
	if _, err := os.Stat(cfg.PolicyDir); err != nil {
		kg.Warn("Policies dir not found for restoration")
		return
	}

	// List all policies files from "/opt/kubearmor/policies" path
	if policyFiles, err := os.ReadDir(cfg.PolicyDir); err == nil {
		for _, file := range policyFiles {
			if data, err := os.ReadFile(cfg.PolicyDir + file.Name()); err == nil {
				var hostPolicy tp.HostSecurityPolicy
				if err := json.Unmarshal(data, &hostPolicy); err == nil {
					dm.HostSecurityPolicies = append(dm.HostSecurityPolicies, hostPolicy)
				}
			}
		}

		if len(policyFiles) != 0 {
			dm.UpdateHostSecurityPolicies()
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

// ===================== //
// == Default Posture == //
// ===================== //

func validateDefaultPosture(key string, ns *corev1.Namespace, defaultPosture string) string {
	if posture, ok := ns.Annotations[key]; ok {
		if posture == "audit" || posture == "Audit" {
			return "audit"
		} else if posture == "block" || posture == "Block" {
			return "block"
		}
		// Invalid Annotation Value, Updating the value to global default
		ns.Annotations[key] = defaultPosture
		updatedNS, err := K8s.K8sClient.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
		if err != nil {
			kg.Warnf("Error updating invalid default posture annotation for %v", updatedNS)
		}
	}
	return defaultPosture
}

// UpdateDefaultPosture Function
func (dm *KubeArmorDaemon) UpdateDefaultPosture(action string, namespace string, defaultPosture tp.DefaultPosture) {
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	dm.DefaultPosturesLock.Lock()
	defer dm.DefaultPosturesLock.Unlock()

	if action == "DELETED" {
		delete(dm.DefaultPostures, namespace)
	}

	dm.DefaultPostures[namespace] = defaultPosture

	dm.Logger.UpdateDefaultPosture(action, namespace, defaultPosture)

	for idx, endPoint := range dm.EndPoints {
		// update a security policy
		if namespace == endPoint.NamespaceName {
			if dm.EndPoints[idx].DefaultPosture == defaultPosture {
				continue
			}

			dm.EndPoints[idx].DefaultPosture = defaultPosture
			dm.Logger.Printf("Updating default posture for %s with %v/%v", endPoint.EndPointName, dm.EndPoints[idx].DefaultPosture, dm.DefaultPostures[namespace])

			if cfg.GlobalCfg.Policy {
				// update security policies
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

// WatchDefaultPosture Function
func (dm *KubeArmorDaemon) WatchDefaultPosture() {
	factory := informers.NewSharedInformerFactory(K8s.K8sClient, 0)
	informer := factory.Core().V1().Namespaces().Informer()

	informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			if ns, ok := obj.(*corev1.Namespace); ok {
				defaultPosture := tp.DefaultPosture{
					FileAction:         validateDefaultPosture("kubearmor-file-posture", ns, cfg.GlobalCfg.DefaultFilePosture),
					NetworkAction:      validateDefaultPosture("kubearmor-network-posture", ns, cfg.GlobalCfg.DefaultNetworkPosture),
					CapabilitiesAction: validateDefaultPosture("kubearmor-capabilities-posture", ns, cfg.GlobalCfg.DefaultCapabilitiesPosture),
				}
				dm.UpdateDefaultPosture("ADDED", ns.Name, defaultPosture)
			}
		},
		UpdateFunc: func(old, new interface{}) {
			if ns, ok := new.(*corev1.Namespace); ok {
				defaultPosture := tp.DefaultPosture{
					FileAction:         validateDefaultPosture("kubearmor-file-posture", ns, cfg.GlobalCfg.DefaultFilePosture),
					NetworkAction:      validateDefaultPosture("kubearmor-network-posture", ns, cfg.GlobalCfg.DefaultNetworkPosture),
					CapabilitiesAction: validateDefaultPosture("kubearmor-capabilities-posture", ns, cfg.GlobalCfg.DefaultCapabilitiesPosture),
				}
				dm.UpdateDefaultPosture("MODIFIED", ns.Name, defaultPosture)
			}
		},
		DeleteFunc: func(obj interface{}) {
			if ns, ok := obj.(*corev1.Namespace); ok {
				dm.UpdateDefaultPosture("DELETED", ns.Name, tp.DefaultPosture{})
			}
		},
	})

	go factory.Start(wait.NeverStop)
	factory.WaitForCacheSync(wait.NeverStop)
	dm.Logger.Print("Started watching Default Posture Annotations")
}
