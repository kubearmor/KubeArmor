// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"maps"
	"os"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/monitor"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	ksp "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/api/security.kubearmor.com/v1"
	kspinformer "github.com/kubearmor/KubeArmor/pkg/KubeArmorController/client/informers/externalversions"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
)

const (
	KubeArmorPolicy        string = "KubeArmorPolicy"
	KubeArmorClusterPolicy string = "KubeArmorClusterPolicy"
	InOperator             string = "In"
	NotInOperator          string = "NotIn"
	NamespaceKey           string = "namespace"
	LabelKey               string = "label"

	// Event Types
	addEvent    string = "ADDED"
	updateEvent string = "MODIFIED"
	deleteEvent string = "DELETED"
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

	// == LSM == //
	var lsm string

	// Check if enforcer is set in the node annotations
	if v, ok := node.Labels["kubearmor.io/enforcer"]; ok {
		lsm = v
	} else { // Read the lsm from the system
		lsmByteData, err := os.ReadFile("/sys/kernel/security/lsm")
		if err != nil && !os.IsNotExist(err) {
			kg.Errf("Failed to read /sys/kernel/security/lsm (%s)", err.Error())
		} else if len(lsmByteData) == 0 {
			kg.Err("Failed to read /sys/kernel/security/lsm: empty file")
		}
		lsm = string(lsmByteData)
	}

	hasAppArmor := strings.Contains(lsm, "apparmor")
	hasSelinux := strings.Contains(lsm, "selinux")
	hasBPF := strings.Contains(lsm, "bpf")

	if !hasBPF && !hasSelinux && !hasAppArmor {
		// exception: neither AppArmor, SELinux or BPF
		if node.Annotations["kubearmor-policy"] == "enabled" {
			node.Annotations["kubearmor-policy"] = "audited"
		}
	}

	if kl.IsInK8sCluster() && hasSelinux {
		// exception: KubeArmor in a daemonset even though SELinux is enabled
		if node.Annotations["kubearmor-policy"] == "enabled" {
			node.Annotations["kubearmor-policy"] = "audited"
		}
	}

	switch node.Annotations["kubearmor-policy"] {
	case "enabled":
		node.PolicyEnabled = tp.KubeArmorPolicyEnabled
	case "audited":
		node.PolicyEnabled = tp.KubeArmorPolicyAudited
	default: // disabled
		node.PolicyEnabled = tp.KubeArmorPolicyDisabled
	}

	if _, ok := node.Annotations["kubearmor-visibility"]; !ok {
		node.Annotations["kubearmor-visibility"] = cfg.GlobalCfg.HostVisibility
	}

	for visibility := range strings.SplitSeq(node.Annotations["kubearmor-visibility"], ",") {
		switch visibility {
		case "process":
			node.ProcessVisibilityEnabled = true
		case "file":
			node.FileVisibilityEnabled = true
		case "network":
			node.NetworkVisibilityEnabled = true
		case "capabilities":
			node.CapabilitiesVisibilityEnabled = true
		}
	}
}

func (dm *KubeArmorDaemon) checkAndUpdateNode(item *corev1.Node) {
	node := tp.Node{}

	node.ClusterName = cfg.GlobalCfg.Cluster
	node.NodeName = cfg.GlobalCfg.Host

	for _, address := range item.Status.Addresses {
		if address.Type == "InternalIP" {
			node.NodeIP = address.Address
			break
		}
	}

	node.Annotations = map[string]string{}
	node.Labels = map[string]string{}
	node.Identities = []string{}

	// update annotations
	maps.Copy(node.Annotations, item.ObjectMeta.Annotations)

	// update labels and identities
	for k, v := range item.ObjectMeta.Labels {
		node.Labels[k] = v
		node.Identities = append(node.Identities, k+"="+v)
	}

	slices.Sort(node.Identities)

	// node info
	node.Architecture = item.Status.NodeInfo.Architecture
	node.OperatingSystem = item.Status.NodeInfo.OperatingSystem
	node.OSImage = item.Status.NodeInfo.OSImage
	node.KernelVersion = item.Status.NodeInfo.KernelVersion
	node.KubeletVersion = item.Status.NodeInfo.KubeletVersion

	// container runtime
	node.ContainerRuntimeVersion = item.Status.NodeInfo.ContainerRuntimeVersion

	dm.HandleNodeAnnotations(&node)

	// update node info
	dm.NodeLock.Lock()
	dm.Node = node
	dm.NodeLock.Unlock()
}

// WatchK8sNodes Function
func (dm *KubeArmorDaemon) WatchK8sNodes() {
	kg.Printf("GlobalCfg.Host=%s, KUBEARMOR_NODENAME=%s", cfg.GlobalCfg.Host, os.Getenv("KUBEARMOR_NODENAME"))

	nodeName := os.Getenv("KUBEARMOR_NODENAME")
	if nodeName == "" {
		nodeName = cfg.GlobalCfg.Host
	}

	factory := informers.NewSharedInformerFactoryWithOptions(
		K8s.K8sClient,
		0,
		informers.WithTweakListOptions(func(options *metav1.ListOptions) {
			options.FieldSelector = fmt.Sprintf("metadata.name=%s", nodeName)
		}),
	)
	informer := factory.Core().V1().Nodes().Informer()

	if _, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if item, ok := obj.(*corev1.Node); ok {
				dm.checkAndUpdateNode(item)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if item, ok := newObj.(*corev1.Node); ok {
				dm.checkAndUpdateNode(item)
			}
		},
	}); err != nil {
		kg.Err("Couldn't Start Watching node information")
		return
	}

	go factory.Start(StopChan)
	factory.WaitForCacheSync(StopChan)
	kg.Print("Started watching node information")

}

// ================ //
// == Pod Update == //
// ================ //

// UpdateEndPointWithPod Function
func (dm *KubeArmorDaemon) UpdateEndPointWithPod(action string, pod tp.K8sPod) {
	if action == addEvent {
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

		slices.Sort(newPoint.Identities)

		// update policy flag
		switch pod.Annotations["kubearmor-policy"] {
		case "enabled":
			newPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
		case "audited":
			newPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
		default: // disabled
			newPoint.PolicyEnabled = tp.KubeArmorPolicyDisabled
		}

		// parse annotations and update visibility flags
		for visibility := range strings.SplitSeq(pod.Annotations["kubearmor-visibility"], ",") {
			switch visibility {
			case "process":
				newPoint.ProcessVisibilityEnabled = true
			case "file":
				newPoint.FileVisibilityEnabled = true
			case "network":
				newPoint.NetworkVisibilityEnabled = true
			case "capabilities":
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
		dm.ContainersLock.Lock()

		// update containers and apparmors
		for _, containerID := range newPoint.Containers {

			container := dm.Containers[containerID]

			container.NamespaceName = newPoint.NamespaceName
			container.EndPointName = newPoint.EndPointName

			if (container.Owner == tp.PodOwner{}) && (len(dm.OwnerInfo) > 0) {
				if podOwnerInfo, ok := dm.OwnerInfo[container.EndPointName]; ok && (podOwnerInfo != tp.PodOwner{}) {
					container.Owner = podOwnerInfo
				}
			}

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

			// if container is privileged
			if _, ok := pod.PrivilegedContainers[container.ContainerName]; ok {
				container.Privileged = true
			}

			dm.Containers[containerID] = container

			// in case if container runtime detect the container and emit that event before pod event then
			// the container id will be added to NsMap with "Unknown" namespace
			// therefore update the NsMap to have this container id with associated namespace
			// and delete the container id from  NamespacePidsMap within "Unknown" namespace
			dm.HandleUnknownNamespaceNsMap(&container)
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
			newPoint.DefaultPosture = globalDefaultPosture
		}
		dm.DefaultPosturesLock.Unlock()

		// update security policies with the identities
		newPoint.SecurityPolicies = dm.GetSecurityPolicies(newPoint)

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

		dm.EndPointsLock.Unlock()

		if cfg.GlobalCfg.Policy {
			// update security policies
			for _, endpoint := range endpoints {
				dm.Logger.UpdateSecurityPolicies(action, endpoint)
				if newPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					if !kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), endpoint.NamespaceName) || action == deleteEvent {
						// we want to avoid new policies in untracked namespaces but deletion of the existing policies should be allowed
						if dm.RuntimeEnforcer != nil {
							dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
						}
						if dm.Presets != nil {
							dm.Presets.UpdateSecurityPolicies(endpoint)
						}
					} else {
						dm.Logger.Warnf("Policy cannot be enforced in untracked namespace %s", endpoint.NamespaceName)
					}
				}
			}
		}

	} else if action == updateEvent {
		newEndPoint := tp.EndPoint{}
		endpoints := []tp.EndPoint{}

		dm.EndPointsLock.RLock()
		for _, endPoint := range dm.EndPoints {
			if pod.Metadata["namespaceName"] == endPoint.NamespaceName && pod.Metadata["podName"] == endPoint.EndPointName {
				endpoints = append(endpoints, endPoint)
				break
			}
		}
		dm.EndPointsLock.RUnlock()
		if len(endpoints) == 0 {
			// No endpoints were added as containers ID have been just added
			// Same logic as ADDED
			dm.UpdateEndPointWithPod(addEvent, pod)

		} else {
			newEndPoint.NamespaceName = pod.Metadata["namespaceName"]
			newEndPoint.EndPointName = pod.Metadata["podName"]
			newEndPoint.Labels = map[string]string{}
			newEndPoint.Identities = []string{"namespaceName=" + pod.Metadata["namespaceName"]}

			// update labels and identities
			for k, v := range pod.Labels {
				newEndPoint.Labels[k] = v
				newEndPoint.Identities = append(newEndPoint.Identities, k+"="+v)
			}

			slices.Sort(newEndPoint.Identities)

			// update policy flag
			switch pod.Annotations["kubearmor-policy"] {
			case "enabled":
				newEndPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
			case "audited":
				newEndPoint.PolicyEnabled = tp.KubeArmorPolicyAudited
			default: // disabled
				newEndPoint.PolicyEnabled = tp.KubeArmorPolicyDisabled
			}

			newEndPoint.ProcessVisibilityEnabled = false
			newEndPoint.FileVisibilityEnabled = false
			newEndPoint.NetworkVisibilityEnabled = false
			newEndPoint.CapabilitiesVisibilityEnabled = false

			// parse annotations and update visibility flags
			for visibility := range strings.SplitSeq(pod.Annotations["kubearmor-visibility"], ",") {
				switch visibility {
				case "process":
					newEndPoint.ProcessVisibilityEnabled = true
				case "file":
					newEndPoint.FileVisibilityEnabled = true
				case "network":
					newEndPoint.NetworkVisibilityEnabled = true
				case "capabilities":
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

			dm.ContainersLock.Lock()
			// update containers and apparmors
			for _, containerID := range newEndPoint.Containers {
				container := dm.Containers[containerID]
				container.NamespaceName = newEndPoint.NamespaceName
				container.EndPointName = newEndPoint.EndPointName
				if (container.Owner == tp.PodOwner{}) && (len(dm.OwnerInfo) > 0) {
					if podOwnerInfo, ok := dm.OwnerInfo[container.EndPointName]; ok && (podOwnerInfo != tp.PodOwner{}) {
						container.Owner = podOwnerInfo
					}
				}
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

				// if container is privileged
				if _, ok := pod.PrivilegedContainers[container.ContainerName]; ok {
					container.Privileged = true
				}
				dm.Containers[containerID] = container

				// in case if container runtime detect the container and emit that event before pod event then
				// the container id will be added to NsMap with "Unknown" namespace
				// therefore update the NsMap to have this container id with associated namespace
				// and delete the container id from  NamespacePidsMap within "Unknown" namespace
				dm.HandleUnknownNamespaceNsMap(&container)
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
				newEndPoint.DefaultPosture = globalDefaultPosture
			}
			dm.DefaultPosturesLock.Unlock()

			// get security policies according to the updated identities
			newEndPoint.SecurityPolicies = dm.GetSecurityPolicies(newEndPoint)

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
			dm.EndPointsLock.Unlock()
			for _, endpoint := range endpoints {
				if cfg.GlobalCfg.Policy {
					// update security policies
					dm.Logger.UpdateSecurityPolicies(action, endpoint)

					if endpoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
						// enforce security policies
						if !kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), endpoint.NamespaceName) || action == deleteEvent {
							// we want to avoid new policies in untracked namespaces but deletion of the existing policies should be allowed
							if dm.RuntimeEnforcer != nil {
								dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
							}
							if dm.Presets != nil {
								dm.Presets.UpdateSecurityPolicies(endpoint)
							}
						} else {
							dm.Logger.Warnf("Policy cannot be enforced in untracked namespace %s", endpoint.NamespaceName)
						}
					}
				}
			}
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

// HandleUnknownNamespaceNsMap Function
func (dm *KubeArmorDaemon) HandleUnknownNamespaceNsMap(container *tp.Container) {
	dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
	dm.SystemMonitor.NsMapLock.Lock()
	if val, ok := dm.SystemMonitor.NamespacePidsMap["Unknown"]; ok {
		for i := range val.NsKeys {
			if val.NsKeys[i].MntNS == container.MntNS && val.NsKeys[i].PidNS == container.PidNS {
				val.NsKeys = append(val.NsKeys[:i], val.NsKeys[i+1:]...)
				break
			}
		}
		dm.SystemMonitor.NamespacePidsMap["Unknown"] = val
	}
	dm.SystemMonitor.NsMapLock.Unlock()
}

func (dm *KubeArmorDaemon) handlePodEvent(event string, obj *corev1.Pod) {
	if event != addEvent && event != updateEvent && event != deleteEvent {
		return
	}

	// create a pod

	pod := tp.K8sPod{}
	containers := []string{}

	// need this for apparmor profile
	var podOwnerName string

	pod.Metadata = map[string]string{}
	pod.Metadata["namespaceName"] = obj.ObjectMeta.Namespace
	pod.Metadata["podName"] = obj.ObjectMeta.Name
	var controllerName, controller, namespace string
	var err error
	dm.OwnerInfoLock.Lock()

	if event == addEvent {
		controllerName, controller, namespace, err = getTopLevelOwner(obj.ObjectMeta, obj.Namespace, obj.Kind)
		if err != nil {
			dm.Logger.Warnf("Failed to get ownerRef (%s, %s)", obj.ObjectMeta.Name, err.Error())
		}

		owner := tp.PodOwner{
			Name:      controllerName,
			Ref:       controller,
			Namespace: namespace,
		}

		dm.OwnerInfo[pod.Metadata["podName"]] = owner
		podOwnerName = controllerName

	}

	// for event = UpdateEvent we first check pod's existence to update current dm.OwnerInfo of the pod, because when pod is in terminating state then we cannot get the owner info from it.
	// we do not update owner info in terminating state. After pod is deleted we delete the owner info from the map.
	_, err = K8s.K8sClient.CoreV1().Pods(namespace).Get(context.Background(), obj.ObjectMeta.Name, metav1.GetOptions{})
	if err == nil && event == updateEvent {
		controllerName, controller, namespace, err = getTopLevelOwner(obj.ObjectMeta, obj.Namespace, obj.Kind)
		if err != nil {
			dm.Logger.Warnf("Failed to get ownerRef (%s, %s)", obj.ObjectMeta.Name, err.Error())
		}

		owner := tp.PodOwner{
			Name:      controllerName,
			Ref:       controller,
			Namespace: namespace,
		}

		dm.OwnerInfo[pod.Metadata["podName"]] = owner
		podOwnerName = controllerName
	}
	dm.OwnerInfoLock.Unlock()

	//get the owner , then check if that owner has owner if...do it recusivelt until you get the no owner

	pod.Annotations = map[string]string{}
	maps.Copy(pod.Annotations, obj.Annotations)

	pod.Labels = map[string]string{}
	for k, v := range obj.Labels {
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

	// add pod labels in podlabels map
	labels := []string{}
	for k, v := range pod.Labels {
		labels = append(labels, k+"="+v)
	}
	dm.SystemMonitor.PodLabelsMapLock.Lock()
	dm.SystemMonitor.PodLabelsMap[pod.Metadata["podName"]] = strings.Join(labels, ",")
	dm.SystemMonitor.PodLabelsMapLock.Unlock()

	pod.Containers = map[string]string{}
	pod.ContainerImages = map[string]string{}
	for _, container := range obj.Status.ContainerStatuses {
		if len(container.ContainerID) > 0 {
			cid := strings.Split(container.ContainerID, "://")
			if len(cid) == 2 { // always true because k8s spec defines format as '<type>://<container_id>'
				containerID := cid[1]
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
	// if _, ok := pod.Labels["kubearmor-app"]; ok {
	// 	pod.Annotations["kubearmor-policy"] = "audited"
	// }

	// == Visibility == //

	if _, ok := pod.Annotations["kubearmor-visibility"]; !ok {
		pod.Annotations["kubearmor-visibility"] = cfg.GlobalCfg.Visibility
	}

	// == AppArmor == //

	if event == addEvent || event == updateEvent {
		exist := false

		dm.K8sPodsLock.RLock()
		for _, k8spod := range dm.K8sPods {
			if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
				if k8spod.Annotations["kubearmor-policy"] == "patched" {
					exist = true
					break
				}
			}
		}
		dm.K8sPodsLock.RUnlock()

		if exist {
			return
		}
	}

	pod.PrivilegedContainers = make(map[string]struct{})
	pod.PrivilegedAppArmorProfiles = make(map[string]struct{})
	if dm.RuntimeEnforcer != nil && dm.RuntimeEnforcer.EnforcerType == "AppArmor" {
		appArmorAnnotations := map[string]string{}
		updateAppArmor := false
		dm.OwnerInfoLock.RLock()
		if dm.OwnerInfo[pod.Metadata["podName"]].Name != "" {
			switch dm.OwnerInfo[pod.Metadata["podName"]].Ref {
			case "StatefulSet":
				statefulset, err := K8s.K8sClient.AppsV1().StatefulSets(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range statefulset.Spec.Template.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}
			case "ReplicaSet":
				replica, err := K8s.K8sClient.AppsV1().ReplicaSets(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range replica.Spec.Template.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}
			case "DaemonSet":
				daemon, err := K8s.K8sClient.AppsV1().DaemonSets(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range daemon.Spec.Template.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}
			case "Deployment":
				deploy, err := K8s.K8sClient.AppsV1().Deployments(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range deploy.Spec.Template.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}
			case "Pod":
				pod, err := K8s.K8sClient.CoreV1().Pods(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range pod.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}

			case "Job":
				job, err := K8s.K8sClient.BatchV1().Jobs(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range job.Spec.Template.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}

			case "CronJob":
				cronJob, err := K8s.K8sClient.BatchV1().CronJobs(pod.Metadata["namespaceName"]).Get(context.Background(), podOwnerName, metav1.GetOptions{})
				if err == nil {
					for _, c := range cronJob.Spec.JobTemplate.Spec.Template.Spec.Containers {
						containers = append(containers, c.Name)
					}
				}

			}

		}
		dm.OwnerInfoLock.RUnlock()

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

		for _, container := range obj.Spec.Containers {
			var privileged bool
			// store privileged containers
			if container.SecurityContext != nil &&
				((container.SecurityContext.Privileged != nil && *container.SecurityContext.Privileged) ||
					(container.SecurityContext.Capabilities != nil && len(container.SecurityContext.Capabilities.Add) > 0)) {
				pod.PrivilegedContainers[container.Name] = struct{}{}
				privileged = true
			}
			profileName := "kubearmor-" + pod.Metadata["namespaceName"] + "-" + podOwnerName + "-" + container.Name
			if _, ok := appArmorAnnotations[container.Name]; !ok && kl.ContainsElement(containers, container.Name) {
				appArmorAnnotations[container.Name] = profileName
				updateAppArmor = true
				// if the container is privileged or it has more than one capabilities added
				// handle the apparmor profile generation with privileged rules
			}
			if privileged {
				// container name is unique for all containers in a pod
				pod.PrivilegedAppArmorProfiles[profileName] = struct{}{}
			}
		}

		if event == addEvent {
			// update apparmor profiles
			dm.RuntimeEnforcer.UpdateAppArmorProfiles(pod.Metadata["podName"], addEvent, appArmorAnnotations, pod.PrivilegedAppArmorProfiles)
			dm.OwnerInfoLock.RLock()
			if updateAppArmor && pod.Annotations["kubearmor-policy"] == "enabled" && dm.OwnerInfo[pod.Metadata["podName"]].Ref != "Pod" {

				// patch deployments only when kubearmor-controller is not present
				if dm.OwnerInfo[pod.Metadata["podName"]].Name != "" && cfg.GlobalCfg.AnnotateResources {
					deploymentName := dm.OwnerInfo[pod.Metadata["podName"]].Name
					// patch the deployment with apparmor annotations
					if err := K8s.PatchResourceWithAppArmorAnnotations(pod.Metadata["namespaceName"], deploymentName, appArmorAnnotations, dm.OwnerInfo[pod.Metadata["podName"]].Ref); err != nil {
						dm.Logger.Errf("Failed to update AppArmor Annotations (%s/%s/%s, %s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"], err.Error())
					} else {
						dm.Logger.Printf("Patched AppArmor Annotations (%s/%s/%s)", pod.Metadata["namespaceName"], deploymentName, pod.Metadata["podName"])
					}
					pod.Annotations["kubearmor-policy"] = "patched"
				}
			}
			dm.OwnerInfoLock.RUnlock()

		} else if event == updateEvent {
			dm.OwnerInfoLock.RLock()
			for _, k8spod := range dm.K8sPods {
				if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
					prevPolicyEnabled := "disabled"

					if val, ok := k8spod.Annotations["kubearmor-policy"]; ok {
						prevPolicyEnabled = val
					}

					if updateAppArmor && prevPolicyEnabled != "enabled" && pod.Annotations["kubearmor-policy"] == "enabled" && dm.OwnerInfo[pod.Metadata["podName"]].Ref != "Pod" {

						// patch deployments only when kubearmor-controller is not present
						if dm.OwnerInfo[pod.Metadata["podName"]].Name != "" && cfg.GlobalCfg.AnnotateResources {
							deploymentName := dm.OwnerInfo[pod.Metadata["podName"]].Name
							// patch the deployment with apparmor annotations
							if err := K8s.PatchResourceWithAppArmorAnnotations(pod.Metadata["namespaceName"], deploymentName, appArmorAnnotations, dm.OwnerInfo[pod.Metadata["podName"]].Ref); err != nil {
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
			dm.OwnerInfoLock.RUnlock()
		} else if event == deleteEvent {
			// update apparmor profiles
			dm.RuntimeEnforcer.UpdateAppArmorProfiles(pod.Metadata["podName"], deleteEvent, appArmorAnnotations, pod.PrivilegedAppArmorProfiles)
		}
	}

	dm.K8sPodsLock.Lock()

	if event == addEvent {
		newPod := true
		for _, k8spod := range dm.K8sPods {
			if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
				newPod = false
				break
			}
		}
		if newPod {
			dm.K8sPods = append(dm.K8sPods, pod)
		} else {
			// Kubernetes can send us 'ADDED' events for a pod we
			// already know about when our Kubernetes watch request
			// restarts, so treat that like a 'MODIFIED' event
			// instead
			event = updateEvent
		}
	}

	if event == updateEvent {
		for idx, k8spod := range dm.K8sPods {
			if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
				dm.K8sPods[idx] = pod
				break
			}
		}
	} else if event == deleteEvent {
		for idx, k8spod := range dm.K8sPods {
			if k8spod.Metadata["namespaceName"] == pod.Metadata["namespaceName"] && k8spod.Metadata["podName"] == pod.Metadata["podName"] {
				dm.K8sPods = append(dm.K8sPods[:idx], dm.K8sPods[idx+1:]...)
				delete(dm.OwnerInfo, pod.Metadata["podName"])
				delete(dm.SystemMonitor.PodLabelsMap, pod.Metadata["podName"])
				break
			}
		}
	}

	dm.K8sPodsLock.Unlock()

	if pod.Annotations["kubearmor-policy"] == "patched" {
		dm.Logger.Printf("Detected a Pod (patched/%s/%s)", pod.Metadata["namespaceName"], pod.Metadata["podName"])
	} else {
		dm.Logger.Printf("Detected a Pod (%s/%s/%s)", strings.ToLower(event), pod.Metadata["namespaceName"], pod.Metadata["podName"])
	}

	// update a endpoint corresponding to the pod
	dm.UpdateEndPointWithPod(event, pod)
}

// WatchK8sPods Function
func (dm *KubeArmorDaemon) WatchK8sPods() {

	if !kl.IsK8sEnv() {
		dm.Logger.Print("not in a k8s environment")
		return
	}

	nodeName := os.Getenv("KUBEARMOR_NODENAME")
	if nodeName == "" {
		nodeName = cfg.GlobalCfg.Host
	}

	nodeFieldSelector := informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		opts.FieldSelector = fmt.Sprintf("spec.nodeName=%s", nodeName)
	})
	factory := informers.NewSharedInformerFactoryWithOptions(K8s.K8sClient, 0, nodeFieldSelector)
	informer := factory.Core().V1().Pods().Informer()

	var err error
	if _, err = informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				if pod, ok := obj.(*corev1.Pod); ok {
					dm.handlePodEvent(addEvent, pod)
				}
			},
			UpdateFunc: func(_, newObj any) {
				if pod, ok := newObj.(*corev1.Pod); ok {
					dm.handlePodEvent(updateEvent, pod)
				}
			},
			DeleteFunc: func(obj any) {
				if pod, ok := obj.(*corev1.Pod); ok {
					dm.handlePodEvent(deleteEvent, pod)
				}
			},
		},
	); err != nil {
		dm.Logger.Warnf("Error starting pod informer=%s", err)
		return
	}

	go factory.Start(StopChan)
	dm.Logger.Print("Started watching pod information")

}

// updateNamespaceListforCSP - in case of NotIn operator for namespace key, a new ns might be added later
// and here we will update namespaceList for CSP
func updateNamespaceListforCSP(policy *tp.SecurityPolicy) {
	if len(policy.Spec.Selector.Identities) > 0 {
		// if is not a Cluster policy, return
		return
	}

	hasInOperator := false
	excludedNamespaces := make(map[string]bool)

	for _, matchExpression := range policy.Spec.Selector.MatchExpressions {
		if matchExpression.Key == "namespace" {
			if matchExpression.Operator == "In" {
				hasInOperator = true
				for _, value := range matchExpression.Values {
					if !kl.ContainsElement(policy.Spec.Selector.NamespaceList, value) {
						policy.Spec.Selector.NamespaceList = append(policy.Spec.Selector.NamespaceList, value)
					}

				}
			} else if matchExpression.Operator == "NotIn" && !hasInOperator {
				for _, value := range matchExpression.Values {
					excludedNamespaces[value] = true
				}
			}
		}
	}

	// this logic will also work when selector is not defined, and policy rule will be applied across all the namespaces
	if !hasInOperator {
		nsList, err := K8s.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
		if err != nil {
			kg.Err("unable to fetch namespace list")
			return
		}

		for _, ns := range nsList.Items {
			if _, ok := excludedNamespaces[ns.Name]; !ok && !kl.ContainsElement(policy.Spec.Selector.NamespaceList, ns.Name) {
				policy.Spec.Selector.NamespaceList = append(policy.Spec.Selector.NamespaceList, ns.Name)
			}
		}
	}
}

// ============================ //
// == Security Policy Update == //
// ============================ //

// GetSecurityPolicies Function
func (dm *KubeArmorDaemon) GetSecurityPolicies(endPoint tp.EndPoint) []tp.SecurityPolicy {
	dm.SecurityPoliciesLock.RLock()
	defer dm.SecurityPoliciesLock.RUnlock()

	secPolicies := []tp.SecurityPolicy{}

	for _, policy := range dm.SecurityPolicies {
		updateNamespaceListforCSP(&policy)

		// match ksp || csp
		if (kl.MatchIdentities(policy.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(policy.Spec.Selector, endPoint.Identities)) ||
			(kl.ContainsElement(policy.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(policy.Spec.Selector, endPoint.Identities)) {
			secPolicy := tp.SecurityPolicy{}
			if err := kl.Clone(policy, &secPolicy); err != nil {
				dm.Logger.Errf("Failed to clone a policy (%s)", err.Error())
			}
			secPolicies = append(secPolicies, secPolicy)
		}
	}

	return secPolicies
}

func containsPolicy(endPointPolicies []tp.SecurityPolicy, secPolicy tp.SecurityPolicy) bool {
	for _, policy := range endPointPolicies {
		if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
			return true
		}
	}
	return false
}

// UpdateSecurityPolicy Function
func (dm *KubeArmorDaemon) UpdateSecurityPolicy(action string, secPolicyType string, secPolicy tp.SecurityPolicy) {
	dm.EndPointsLock.RLock()
	endPointsLength := len(dm.EndPoints)
	dm.EndPointsLock.RUnlock()

	for idx := range endPointsLength {
		dm.EndPointsLock.RLock()
		endPoint := dm.EndPoints[idx]
		dm.EndPointsLock.RUnlock()

		// update a security policy
		if secPolicyType == KubeArmorPolicy {
			if len(secPolicy.Spec.Selector.Containers) == 0 || kl.ContainsElement(secPolicy.Spec.Selector.Containers, endPoint.ContainerName) {
				if action == addEvent {
					if kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(secPolicy.Spec.Selector, endPoint.Identities) {
						// add a new security policy if it doesn't exist
						new := true
						for _, policy := range endPoint.SecurityPolicies {
							if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
								new = false
								break
							}
						}
						if new {
							endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPolicy)
						}
					}
				} else if action == updateEvent {
					// in case new labels are added in the policy, check if identities match, if yes, add policy in endPoint
					addNewPolicy := true
					for idxP, policy := range endPoint.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							if !(kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(secPolicy.Spec.Selector, endPoint.Identities)) {
								endPoint.SecurityPolicies = append(endPoint.SecurityPolicies[:idxP], endPoint.SecurityPolicies[idxP+1:]...)
								addNewPolicy = false
								break
							}
							endPoint.SecurityPolicies[idxP] = secPolicy
							addNewPolicy = false
							break
						}
					}
					// check identities before adding poilicies
					if addNewPolicy && kl.MatchIdentities(secPolicy.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(secPolicy.Spec.Selector, endPoint.Identities) {
						endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPolicy)
					}
				} else if action == deleteEvent {
					// remove the given policy from the security policy list of this endpoint
					for idxP, policy := range endPoint.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							endPoint.SecurityPolicies = append(endPoint.SecurityPolicies[:idxP], endPoint.SecurityPolicies[idxP+1:]...)
							break
						}
					}
				}

				dm.EndPointsLock.Lock()
				dm.EndPoints[idx] = endPoint
				dm.EndPointsLock.Unlock()

				if cfg.GlobalCfg.Policy {
					// update security policies
					dm.Logger.UpdateSecurityPolicies("UPDATED", endPoint)

					if dm.EndPoints[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
						// enforce security policies
						if !kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), dm.EndPoints[idx].NamespaceName) || action == deleteEvent {
							// we want to avoid new policies in untracked namespaces but deletion of the existing policies should be allowed
							if dm.RuntimeEnforcer != nil {
								dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.EndPoints[idx])
							}
							if dm.Presets != nil {
								dm.Presets.UpdateSecurityPolicies(dm.EndPoints[idx])
							}
						} else {
							dm.Logger.Warnf("Policy cannot be enforced in untracked namespace %s", dm.EndPoints[idx].NamespaceName)
						}
					}

				}
			}
		} else if secPolicyType == KubeArmorClusterPolicy {
			// additional OR check added with containsPolicy() is when this endPoint's ns is removed from secPolicy.Spec.Selector.MatchExpressions[i].Values
			// due to which secPolicy.Spec.Selector.NamespaceList will not have the removed ns
			if kl.ContainsElement(secPolicy.Spec.Selector.NamespaceList, endPoint.NamespaceName) || containsPolicy(endPoint.SecurityPolicies, secPolicy) {
				if action == addEvent {
					if kl.ContainsElement(secPolicy.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(secPolicy.Spec.Selector, endPoint.Identities) {
						// add a new security policy if it doesn't exist
						new := true
						for _, policy := range endPoint.SecurityPolicies {
							if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
								new = false
								break
							}
						}
						if new {
							endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPolicy)
						}
					}
				} else if action == updateEvent {
					// when policy is modified and new ns is added in secPolicy.Spec.Selector.MatchExpressions[i].Values
					addNewPolicy := true

					for idxP, policy := range endPoint.SecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							if !(kl.ContainsElement(secPolicy.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(secPolicy.Spec.Selector, endPoint.Identities)) {
								// when policy is modified and this endPoint's ns is removed from secPolicy.Spec.Selector.MatchExpressions[i].Values
								endPoint.SecurityPolicies = append(endPoint.SecurityPolicies[:idxP], endPoint.SecurityPolicies[idxP+1:]...)
								addNewPolicy = false
								break
							}
							endPoint.SecurityPolicies[idxP] = secPolicy
							addNewPolicy = false
							break
						}
					}
					// always check identities before adding poilicies
					if addNewPolicy && kl.ContainsElement(secPolicy.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(secPolicy.Spec.Selector, endPoint.Identities) {
						endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPolicy)
					}
				} else if action == deleteEvent {
					// remove the given policy from the security policy list of this endpoint
					for idxP, policy := range endPoint.SecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							endPoint.SecurityPolicies = append(endPoint.SecurityPolicies[:idxP], endPoint.SecurityPolicies[idxP+1:]...)
							break
						}
					}
				}

				dm.EndPointsLock.Lock()
				dm.EndPoints[idx] = endPoint
				dm.EndPointsLock.Unlock()

				if cfg.GlobalCfg.Policy {
					// update security policies
					dm.Logger.UpdateSecurityPolicies("UPDATED", endPoint)

					if dm.EndPoints[idx].PolicyEnabled == tp.KubeArmorPolicyEnabled {
						// enforce security policies
						if !kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), dm.EndPoints[idx].NamespaceName) || action == deleteEvent {
							// we want to avoid new policies in untracked namespaces but deletion of the existing policies should be allowed
							if dm.RuntimeEnforcer != nil {
								dm.RuntimeEnforcer.UpdateSecurityPolicies(dm.EndPoints[idx])
							}
							if dm.Presets != nil {
								dm.Presets.UpdateSecurityPolicies(dm.EndPoints[idx])
							}
						} else {
							dm.Logger.Warnf("Policy cannot be enforced in untracked namespace %s", dm.EndPoints[idx].NamespaceName)
						}
					}
				}
			}
		}
	}
}

// CreateSecurityPolicy - creates `KubeArmorPolicy` & `KubeArmorClusterPolicy` object from crd
func (dm *KubeArmorDaemon) CreateSecurityPolicy(policyType string, securityPolicy any) (secPolicy tp.SecurityPolicy, err error) {
	var namespace, name string

	switch policyType {
	case KubeArmorPolicy:
		kubearmorPolicy := securityPolicy.(ksp.KubeArmorPolicy)

		namespace = kubearmorPolicy.Namespace
		name = kubearmorPolicy.Name
		if err := kl.Clone(kubearmorPolicy.Spec, &secPolicy.Spec); err != nil {
			dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
			return tp.SecurityPolicy{}, err
		}

		// add identities
		secPolicy.Spec.Selector.Identities = []string{"namespaceName=" + namespace}

		for k, v := range secPolicy.Spec.Selector.MatchLabels {
			if k == "kubearmor.io/container.name" {
				if len(v) > 2 {
					containerArray := v[1 : len(v)-1]
					for container := range strings.SplitSeq(containerArray, ",") {
						if len(container) > 0 {
							secPolicy.Spec.Selector.Containers = append(secPolicy.Spec.Selector.Containers, strings.TrimSpace(container))
						}

					}
				}
			} else {
				secPolicy.Spec.Selector.Identities = append(secPolicy.Spec.Selector.Identities, k+"="+v)
			}
		}

		hasInOperator := false
		for _, matchExpression := range secPolicy.Spec.Selector.MatchExpressions {
			if matchExpression.Key == LabelKey {
				if matchExpression.Operator == InOperator {
					for _, label := range matchExpression.Values {
						hasInOperator = true
						secPolicy.Spec.Selector.MatchExpIdentities = append(secPolicy.Spec.Selector.MatchExpIdentities, label)
					}
				} else if matchExpression.Operator == NotInOperator && !hasInOperator {
					for _, label := range matchExpression.Values {
						secPolicy.Spec.Selector.NonIdentities = append(secPolicy.Spec.Selector.NonIdentities, label)
					}
				}
			}
		}

		slices.Sort(secPolicy.Spec.Selector.Identities)
		slices.Sort(secPolicy.Spec.Selector.MatchExpIdentities)
		slices.Sort(secPolicy.Spec.Selector.NonIdentities)

	case KubeArmorClusterPolicy:
		kubearmorClusterPolicy := securityPolicy.(ksp.KubeArmorClusterPolicy)

		namespace = kubearmorClusterPolicy.Namespace
		name = kubearmorClusterPolicy.Name
		if err := kl.Clone(kubearmorClusterPolicy.Spec, &secPolicy.Spec); err != nil {
			dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
			return tp.SecurityPolicy{}, err
		}

		hasNsInOperator := false
		hasLabelInOperator := false
		excludedNamespaces := make(map[string]bool)

		for _, matchExpression := range secPolicy.Spec.Selector.MatchExpressions {
			switch matchExpression.Key {
			case NamespaceKey:
				if matchExpression.Operator == InOperator {
					hasNsInOperator = true
					secPolicy.Spec.Selector.NamespaceList = append(secPolicy.Spec.Selector.NamespaceList, matchExpression.Values...)
				} else if matchExpression.Operator == NotInOperator && !hasNsInOperator {
					for _, value := range matchExpression.Values {
						excludedNamespaces[value] = true
					}
				}
			case LabelKey:
				if matchExpression.Operator == InOperator {
					for _, label := range matchExpression.Values {
						hasLabelInOperator = true
						secPolicy.Spec.Selector.MatchExpIdentities = append(secPolicy.Spec.Selector.MatchExpIdentities, label)
					}
				} else if matchExpression.Operator == NotInOperator && !hasLabelInOperator {
					for _, label := range matchExpression.Values {
						secPolicy.Spec.Selector.NonIdentities = append(secPolicy.Spec.Selector.NonIdentities, label)
					}
				}
			}
		}

		slices.Sort(secPolicy.Spec.Selector.MatchExpIdentities)
		slices.Sort(secPolicy.Spec.Selector.NonIdentities)

		// this logic will also work when selector is not defined, and policy rule will be applied across all the namespaces
		if !hasNsInOperator {
			nsList, err := K8s.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
			if err != nil {
				kg.Err("unable to fetch namespace list")
				return tp.SecurityPolicy{}, err
			}

			for _, ns := range nsList.Items {
				if _, ok := excludedNamespaces[ns.Name]; !ok {
					secPolicy.Spec.Selector.NamespaceList = append(secPolicy.Spec.Selector.NamespaceList, ns.Name)
				}
			}
		}
	}

	secPolicy.Metadata = map[string]string{}
	secPolicy.Metadata["namespaceName"] = namespace
	secPolicy.Metadata["policyName"] = name

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
	return
}

// WatchSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchSecurityPolicies() cache.InformerSynced {
	for {
		if err := K8s.CheckCustomResourceDefinition("kubearmorpolicies"); err != nil {
			time.Sleep(time.Second * 1)
			continue
		} else {
			break
		}
	}

	factory := kspinformer.NewSharedInformerFactory(K8s.KSPClient, 0)

	informer := factory.Security().V1().KubeArmorPolicies().Informer()
	registration, err := informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				// create a security policy
				if policy, ok := obj.(*ksp.KubeArmorPolicy); ok {

					secPolicy, err := dm.CreateSecurityPolicy(KubeArmorPolicy, *policy)
					if err != nil {
						dm.Logger.Warnf("Error ADD, %s", err)
						return
					}
					dm.SecurityPoliciesLock.Lock()
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
					dm.SecurityPoliciesLock.Unlock()
					dm.Logger.Printf("Detected a Security Policy (added/%s/%s)", secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

					// apply security policies to pods
					dm.UpdateSecurityPolicy(addEvent, KubeArmorPolicy, secPolicy)

				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				if policy, ok := newObj.(*ksp.KubeArmorPolicy); ok {
					secPolicy, err := dm.CreateSecurityPolicy(KubeArmorPolicy, *policy)
					if err != nil {
						return
					}

					dm.SecurityPoliciesLock.Lock()
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies[idx] = secPolicy
							break
						}
					}
					dm.SecurityPoliciesLock.Unlock()

					dm.Logger.Printf("Detected a Security Policy (modified/%s/%s)", secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

					// apply security policies to pods
					dm.UpdateSecurityPolicy(updateEvent, KubeArmorPolicy, secPolicy)
				}
			},
			DeleteFunc: func(obj any) {
				if policy, ok := obj.(*ksp.KubeArmorPolicy); ok {
					secPolicy, err := dm.CreateSecurityPolicy(KubeArmorPolicy, *policy)
					if err != nil {
						return
					}
					dm.SecurityPoliciesLock.Lock()
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["namespaceName"] == secPolicy.Metadata["namespaceName"] && policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
							break
						}
					}
					dm.SecurityPoliciesLock.Unlock()

					dm.Logger.Printf("Detected a Security Policy (deleted/%s/%s)", secPolicy.Metadata["namespaceName"], secPolicy.Metadata["policyName"])

					// apply security policies to pods
					dm.UpdateSecurityPolicy(deleteEvent, KubeArmorPolicy, secPolicy)
				}
			},
		},
	)
	if err != nil {
		dm.Logger.Err("Couldn't start watching KubeArmor Security Policies")
		return nil
	}

	go factory.Start(StopChan)
	return registration.HasSynced
}

// WatchClusterSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchClusterSecurityPolicies(timeout time.Duration) cache.InformerSynced {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	crdFound := false
	for !crdFound {
		select {
		case <-ctx.Done():
			dm.Logger.Warn("timeout while monitoring cluster security policies, kubearmorclusterpolicies CRD not found")
			return nil
		default:
			if err := K8s.CheckCustomResourceDefinition("kubearmorclusterpolicies"); err == nil {
				crdFound = true
			} else {
				time.Sleep(time.Second * 1)
			}
		}
	}

	factory := kspinformer.NewSharedInformerFactory(K8s.KSPClient, 0)

	informer := factory.Security().V1().KubeArmorClusterPolicies().Informer()
	registration, err := informer.AddEventHandler(
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj any) {
				// create a security policy
				if policy, ok := obj.(*ksp.KubeArmorClusterPolicy); ok {

					secPolicy, err := dm.CreateSecurityPolicy(KubeArmorClusterPolicy, *policy)
					if err != nil {
						dm.Logger.Warnf("Error ADD, %s", err)
						return
					}
					dm.SecurityPoliciesLock.Lock()
					new := true
					for _, policy := range dm.SecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							new = false
							break
						}
					}
					if new {
						dm.SecurityPolicies = append(dm.SecurityPolicies, secPolicy)
					}
					dm.SecurityPoliciesLock.Unlock()
					dm.Logger.Printf("Detected a Cluster Security Policy (added/%s)", secPolicy.Metadata["policyName"])

					// apply security policies to pods
					dm.UpdateSecurityPolicy(addEvent, KubeArmorClusterPolicy, secPolicy)

				}
			},
			UpdateFunc: func(oldObj, newObj any) {
				if policy, ok := newObj.(*ksp.KubeArmorClusterPolicy); ok {
					secPolicy, err := dm.CreateSecurityPolicy(KubeArmorClusterPolicy, *policy)
					if err != nil {
						return
					}

					dm.SecurityPoliciesLock.Lock()
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies[idx] = secPolicy
							break
						}
					}
					dm.SecurityPoliciesLock.Unlock()

					dm.Logger.Printf("Detected a Cluster Security Policy (modified/%s)", secPolicy.Metadata["policyName"])

					// apply security policies to pods
					dm.UpdateSecurityPolicy(updateEvent, KubeArmorClusterPolicy, secPolicy)
				}
			},
			DeleteFunc: func(obj any) {
				if policy, ok := obj.(*ksp.KubeArmorClusterPolicy); ok {
					secPolicy, err := dm.CreateSecurityPolicy(KubeArmorClusterPolicy, *policy)
					if err != nil {
						return
					}
					dm.SecurityPoliciesLock.Lock()
					for idx, policy := range dm.SecurityPolicies {
						if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
							dm.SecurityPolicies = append(dm.SecurityPolicies[:idx], dm.SecurityPolicies[idx+1:]...)
							break
						}
					}
					dm.SecurityPoliciesLock.Unlock()

					dm.Logger.Printf("Detected a Cluster Security Policy (deleted/%s)", secPolicy.Metadata["policyName"])

					// apply security policies to pods
					dm.UpdateSecurityPolicy(deleteEvent, KubeArmorClusterPolicy, secPolicy)
				}
			},
		},
	)
	if err != nil {
		dm.Logger.Err("Couldn't start watching KubeArmor Security Policies")
		return nil
	}

	go factory.Start(StopChan)
	return registration.HasSynced
}

// ================================= //
// == Host Security Policy Update == //
// ================================= //

// UpdateHostSecurityPolicies Function
func (dm *KubeArmorDaemon) UpdateHostSecurityPolicies() {
	dm.HostSecurityPoliciesLock.RLock()
	hostSecurityPoliciesLength := len(dm.HostSecurityPolicies)
	dm.HostSecurityPoliciesLock.RUnlock()

	secPolicies := []tp.HostSecurityPolicy{}

	for idx := range hostSecurityPoliciesLength {
		dm.EndPointsLock.RLock()
		policy := dm.HostSecurityPolicies[idx]
		dm.EndPointsLock.RUnlock()

		if kl.MatchIdentities(policy.Spec.NodeSelector.Identities, dm.Node.Identities) {
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

		if dm.USBDeviceHandler != nil {
			if dm.Node.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				// enforce USB device security policies
				dm.USBDeviceHandler.UpdateHostSecurityPolicies(secPolicies)
			}
		}
	}
}

// ParseAndUpdateHostSecurityPolicy Function
func (dm *KubeArmorDaemon) ParseAndUpdateHostSecurityPolicy(event tp.K8sKubeArmorHostPolicyEvent) pb.PolicyStatus {
	// create a host security policy

	secPolicy := tp.HostSecurityPolicy{}

	secPolicy.Metadata = map[string]string{}
	secPolicy.Metadata["policyName"] = event.Object.Metadata.Name

	if err := kl.Clone(event.Object.Spec, &secPolicy.Spec); err != nil {
		dm.Logger.Errf("Failed to clone a spec (%s)", err.Error())
		return pb.PolicyStatus_Failure
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

	slices.Sort(secPolicy.Spec.NodeSelector.Identities)

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

	if len(secPolicy.Spec.Device.MatchDevice) > 0 {
		for idx, device := range secPolicy.Spec.Device.MatchDevice {
			if device.Severity == 0 {
				if secPolicy.Spec.Device.Severity != 0 {
					secPolicy.Spec.Device.MatchDevice[idx].Severity = secPolicy.Spec.Device.Severity
				} else {
					secPolicy.Spec.Device.MatchDevice[idx].Severity = secPolicy.Spec.Severity
				}
			}

			if len(device.Tags) == 0 {
				if len(secPolicy.Spec.Device.Tags) > 0 {
					secPolicy.Spec.Device.MatchDevice[idx].Tags = secPolicy.Spec.Device.Tags
				} else {
					secPolicy.Spec.Device.MatchDevice[idx].Tags = secPolicy.Spec.Tags
				}
			}

			if len(device.Message) == 0 {
				if len(secPolicy.Spec.Device.Message) > 0 {
					secPolicy.Spec.Device.MatchDevice[idx].Message = secPolicy.Spec.Device.Message
				} else {
					secPolicy.Spec.Device.MatchDevice[idx].Message = secPolicy.Spec.Message
				}
			}

			if len(device.Action) == 0 {
				if len(secPolicy.Spec.Device.Action) > 0 {
					secPolicy.Spec.Device.MatchDevice[idx].Action = secPolicy.Spec.Device.Action
				} else {
					secPolicy.Spec.Device.MatchDevice[idx].Action = secPolicy.Spec.Action
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

	if event.Type == addEvent {
		new := true
		for idx, policy := range dm.HostSecurityPolicies {
			if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				if reflect.DeepEqual(policy, secPolicy) {
					kg.Debugf("No updates to policy %s", policy.Metadata["policyName"])
					dm.HostSecurityPoliciesLock.Unlock()
					return pb.PolicyStatus_Applied
				}

				dm.HostSecurityPolicies[idx] = secPolicy
				event.Type = updateEvent
				new = false
				break
			}
		}
		if new {
			dm.HostSecurityPolicies = append(dm.HostSecurityPolicies, secPolicy)
		}
	} else if event.Type == updateEvent {
		for idx, policy := range dm.HostSecurityPolicies {
			if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				if reflect.DeepEqual(policy, secPolicy) {
					kg.Debugf("No updates to policy %s", policy.Metadata["policyName"])
					dm.HostSecurityPoliciesLock.Unlock()
					return pb.PolicyStatus_Applied
				}

				dm.HostSecurityPolicies[idx] = secPolicy
				break
			}
		}
	} else if event.Type == deleteEvent {
		// check that a security policy should exist before performing delete operation
		policymatch := false
		for idx, policy := range dm.HostSecurityPolicies {
			if policy.Metadata["policyName"] == secPolicy.Metadata["policyName"] {
				dm.HostSecurityPolicies = append(dm.HostSecurityPolicies[:idx], dm.HostSecurityPolicies[idx+1:]...)
				policymatch = true
				break
			}
		}
		if !policymatch {
			dm.Logger.Warnf("Failed to delete security policy. Policy doesn't exist")
			dm.HostSecurityPoliciesLock.Unlock()
			return pb.PolicyStatus_NotExist
		}
	}

	dm.HostSecurityPoliciesLock.Unlock()

	dm.Logger.Printf("Detected a Host Security Policy (%s/%s)", strings.ToLower(event.Type), secPolicy.Metadata["policyName"])

	// apply security policies to a host
	dm.UpdateHostSecurityPolicies()

	if !cfg.GlobalCfg.K8sEnv && (cfg.GlobalCfg.KVMAgent || cfg.GlobalCfg.HostPolicy) {
		switch event.Type {
		case addEvent, updateEvent:
			// backup HostSecurityPolicy to file
			dm.backupKubeArmorHostPolicy(secPolicy)
		case deleteEvent:
			dm.removeBackUpPolicy(secPolicy.Metadata["policyName"])
		}
	}
	switch event.Type {
	case addEvent:
		return pb.PolicyStatus_Applied
	case deleteEvent:
		return pb.PolicyStatus_Deleted
	}
	return pb.PolicyStatus_Modified
}

// WatchHostSecurityPolicies Function
func (dm *KubeArmorDaemon) WatchHostSecurityPolicies(timeout time.Duration) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			dm.Logger.Warn("timeout while monitoring host security policies, kubearmorhostpolicies CRD not found")
			return
		default:
			if err := K8s.CheckCustomResourceDefinition("kubearmorhostpolicies"); err != nil {
				time.Sleep(time.Second * 1)
				continue
			}
		}

		dm.Logger.Print("Started to monitor host security policies")

		if err := K8s.CheckCustomResourceDefinition("kubearmorhostpolicies"); err != nil {
			time.Sleep(time.Second * 1)
			continue
		}

		if resp := K8s.WatchK8sHostSecurityPolicies(); resp != nil {
			defer func() {
				if err := resp.Body.Close(); err != nil {
					kg.Warnf("Error closing http stream %s\n", err)
				}
			}()

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

				if event.Type != addEvent && event.Type != updateEvent && event.Type != deleteEvent {
					continue
				}

				dm.ParseAndUpdateHostSecurityPolicy(event)
			}
		}
	}
}

// ===================== //
// == Default Posture == //
// ===================== //

func (dm *KubeArmorDaemon) updatEndpointsWithCM(cm *corev1.ConfigMap, action string) {
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	dm.DefaultPosturesLock.Lock()
	defer dm.DefaultPosturesLock.Unlock()

	// get all namespaces
	nsList, err := K8s.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		kg.Err("unable to fetch namespace list")
		return
	}

	// for each namespace if needed change endpoint depfault posture
	for _, ns := range nsList.Items {
		fp, fa := validateDefaultPosture("kubearmor-file-posture", &ns, cm.Data[cfg.ConfigDefaultFilePosture])
		np, na := validateDefaultPosture("kubearmor-network-posture", &ns, cm.Data[cfg.ConfigDefaultNetworkPosture])
		cp, ca := validateDefaultPosture("kubearmor-capabilities-posture", &ns, cm.Data[cfg.ConfigDefaultCapabilitiesPosture])
		annotated := fa || na || ca      // if namespace is annotated for atleast one posture
		fullyannotated := fa && na && ca // if namespace is fully annotated
		posture := tp.DefaultPosture{
			FileAction:         fp,
			NetworkAction:      np,
			CapabilitiesAction: cp,
		}

		// skip if namespace is fully annotated
		if fullyannotated {
			continue
		}

		for idx, endpoint := range dm.EndPoints {
			// skip all endpoints not in current namespace
			if endpoint.NamespaceName != ns.Name {
				continue
			}

			if endpoint.DefaultPosture != posture { // optimization, only if its needed to update the posture
				dm.Logger.Printf("updating default posture for %s in %s", ns.Name, endpoint.EndPointName)
				dm.UpdateDefaultPostureWithCM(&dm.EndPoints[idx], action, ns.Name, posture, annotated)
			}
		}

	}
}

// UpdateDefaultPostureWithCM Function
func (dm *KubeArmorDaemon) UpdateDefaultPostureWithCM(endPoint *tp.EndPoint, action string, namespace string, defaultPosture tp.DefaultPosture, annotated bool) {

	// namespace is (partialy) annotated with posture annotation(s)
	if annotated {
		// update the dm.DefaultPosture[namespace]
		dm.DefaultPostures[namespace] = defaultPosture
	}
	dm.Logger.UpdateDefaultPosture(action, namespace, defaultPosture)

	// update the endpoint with updated default posture
	endPoint.DefaultPosture = defaultPosture
	dm.Logger.Printf("Updated default posture for %s with %v", endPoint.EndPointName, endPoint.DefaultPosture)
	if cfg.GlobalCfg.Policy {
		// update security policies
		if dm.RuntimeEnforcer != nil {
			if endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
				// enforce security policies
				if !kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), endPoint.NamespaceName) {
					dm.RuntimeEnforcer.UpdateSecurityPolicies(*endPoint)
				} else {
					dm.Logger.Warnf("Policy cannot be enforced in untracked namespace %s", endPoint.NamespaceName)
				}
			}
		}
	}

}

// returns default posture and a boolean value states, if annotation is set or not
func validateDefaultPosture(key string, ns *corev1.Namespace, defaultPosture string) (string, bool) {
	if posture, ok := ns.Annotations[key]; ok {
		switch strings.ToLower(posture) {
		case "audit":
			return "audit", true
		case "block":
			return "block", true
		}
		// Invalid Annotation Value, Updating the value to global default
		ns.Annotations[key] = defaultPosture
		updatedNS, err := K8s.K8sClient.CoreV1().Namespaces().Update(context.Background(), ns, metav1.UpdateOptions{})
		if err != nil {
			kg.Warnf("Error updating invalid default posture annotation for %v", updatedNS)
		}
	}
	return defaultPosture, false
}

// UpdateDefaultPosture Function
func (dm *KubeArmorDaemon) UpdateDefaultPosture(action string, namespace string, defaultPosture tp.DefaultPosture, annotated bool) {
	dm.DefaultPosturesLock.Lock()
	defer dm.DefaultPosturesLock.Unlock()

	// namespace deleted
	if action == deleteEvent {
		_, ok := dm.DefaultPostures[namespace]
		if ok {
			delete(dm.DefaultPostures, namespace)
		}
	}

	// namespace is annotated with posture annotation(s)
	if annotated {
		dm.DefaultPostures[namespace] = defaultPosture
	}
	dm.Logger.UpdateDefaultPosture(action, namespace, defaultPosture)

	dm.EndPointsLock.RLock()
	endPointsLen := len(dm.EndPoints)
	dm.EndPointsLock.RUnlock()

	for idx := range endPointsLen {
		dm.EndPointsLock.RLock()
		endPoint := dm.EndPoints[idx]
		dm.EndPointsLock.RUnlock()
		// update a security policy
		if namespace == endPoint.NamespaceName {
			if endPoint.DefaultPosture == defaultPosture {
				continue
			}

			dm.Logger.Printf("Updating default posture for %s with %v namespace default %v", endPoint.EndPointName, endPoint.DefaultPosture, defaultPosture)
			endPoint.DefaultPosture = defaultPosture

			dm.EndPointsLock.Lock()
			dm.EndPoints[idx] = endPoint
			dm.EndPointsLock.Unlock()

			if cfg.GlobalCfg.Policy {
				// update security policies
				if dm.RuntimeEnforcer != nil {
					if endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
						// enforce security policies
						if !kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), endPoint.NamespaceName) {
							dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
						} else {
							dm.Logger.Warnf("Policy cannot be enforced in untracked namespace %s", endPoint.NamespaceName)
						}

					}
				}
			}
		}
	}
}

func validateGlobalDefaultPosture(posture string) string {
	switch posture {
	case "audit", "Audit":
		return "audit"
	case "block", "Block":
		return "block"
	default:
		return "audit"
	}
}

// ======================== //
// == Default Visibility == //
// ======================== //

func (dm *KubeArmorDaemon) validateVisibility(scope string, visibility string) bool {
	return strings.Contains(visibility, scope)
}

// UpdateVisibility Function
func (dm *KubeArmorDaemon) UpdateVisibility(action string, namespace string, visibility tp.Visibility) {
	dm.SystemMonitor.BpfMapLock.Lock()
	defer dm.SystemMonitor.BpfMapLock.Unlock()

	switch action {
	case addEvent, updateEvent:
		if val, ok := dm.SystemMonitor.NamespacePidsMap[namespace]; ok {
			val.Capability = visibility.Capabilities
			val.File = visibility.File
			val.Network = visibility.Network
			val.Process = visibility.Process
			val.DNS = visibility.DNS
			val.IMA = visibility.IMA
			dm.SystemMonitor.NamespacePidsMap[namespace] = val
			for _, nskey := range val.NsKeys {
				dm.SystemMonitor.UpdateNsKeyMap(updateEvent, nskey, visibility)
			}
		} else {
			dm.SystemMonitor.NamespacePidsMap[namespace] = monitor.NsVisibility{
				NsKeys:     []monitor.NsKey{},
				File:       visibility.File,
				Process:    visibility.Process,
				Capability: visibility.Capabilities,
				Network:    visibility.Network,
				DNS:        visibility.DNS,
				IMA:        visibility.IMA,
			}
		}
		dm.Logger.Printf("Namespace %s visibiliy configured %+v", namespace, visibility)
	case deleteEvent:
		if val, ok := dm.SystemMonitor.NamespacePidsMap[namespace]; ok {
			for _, nskey := range val.NsKeys {
				dm.SystemMonitor.UpdateNsKeyMap(deleteEvent, nskey, tp.Visibility{})
			}
		}
		delete(dm.SystemMonitor.NamespacePidsMap, namespace)
	}
}

var visibilityKey string = "kubearmor-visibility"

func (dm *KubeArmorDaemon) updateVisibilityWithCM(cm *corev1.ConfigMap, _ string) {

	dm.SystemMonitor.UpdateVisibility() // update host and global default bpf maps

	// get all namespaces
	nsList, err := K8s.K8sClient.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		kg.Err("unable to fetch namespace list")
		return
	}

	for _, ns := range nsList.Items {
		// 1. If namespace is untracked → explicitly remove visibility
		if kl.ContainsElement(cfg.GlobalCfg.ConfigUntrackedNs.Load().([]string), ns.Name) {
			//update visibility to empty for untracked namespaces
			dm.UpdateVisibility(updateEvent, ns.Name, tp.Visibility{})
			continue
		}

		// 2. If namespace has visibility annotation → skip CM-based updates
		if _, found := ns.Annotations[visibilityKey]; found {
			continue
		}

		visibility := tp.Visibility{
			File:         strings.Contains(cm.Data[cfg.ConfigVisibility], "file"),
			Process:      strings.Contains(cm.Data[cfg.ConfigVisibility], "process"),
			Network:      strings.Contains(cm.Data[cfg.ConfigVisibility], "network"),
			Capabilities: strings.Contains(cm.Data[cfg.ConfigVisibility], "capabilities"),
			DNS:          strings.Contains(cm.Data[cfg.ConfigVisibility], "dns"),
			IMA:          strings.Contains(cm.Data[cfg.ConfigVisibility], "ima"),
		}
		dm.UpdateVisibility(updateEvent, ns.Name, visibility)
	}
}

// UpdateGlobalPosture Function
func (dm *KubeArmorDaemon) UpdateGlobalPosture(posture tp.DefaultPosture) {
	dm.EndPointsLock.Lock()
	defer dm.EndPointsLock.Unlock()

	dm.DefaultPosturesLock.Lock()
	defer dm.DefaultPosturesLock.Unlock()

	cfg.GlobalCfg.DefaultFilePosture = validateGlobalDefaultPosture(posture.FileAction)
	cfg.GlobalCfg.DefaultNetworkPosture = validateGlobalDefaultPosture(posture.NetworkAction)
	cfg.GlobalCfg.DefaultCapabilitiesPosture = validateGlobalDefaultPosture(posture.CapabilitiesAction)
	cfg.GlobalCfg.HostDefaultDevicePosture = validateGlobalDefaultPosture(posture.DeviceAction)

	dm.Logger.Printf("[Update] Global DefaultPosture {File:%v, Capabilities:%v, Network:%v, Device:%v}",
		cfg.GlobalCfg.DefaultFilePosture,
		cfg.GlobalCfg.DefaultCapabilitiesPosture,
		cfg.GlobalCfg.DefaultNetworkPosture,
		cfg.GlobalCfg.HostDefaultDevicePosture)

}

// WatchDefaultPosture Function
func (dm *KubeArmorDaemon) WatchDefaultPosture() cache.InformerSynced {
	factory := informers.NewSharedInformerFactory(K8s.K8sClient, 0)
	informer := factory.Core().V1().Namespaces().Informer()

	registration, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if ns, ok := obj.(*corev1.Namespace); ok {
				fp, fa := validateDefaultPosture("kubearmor-file-posture", ns, cfg.GlobalCfg.DefaultFilePosture)
				np, na := validateDefaultPosture("kubearmor-network-posture", ns, cfg.GlobalCfg.DefaultNetworkPosture)
				cp, ca := validateDefaultPosture("kubearmor-capabilities-posture", ns, cfg.GlobalCfg.DefaultCapabilitiesPosture)
				defaultPosture := tp.DefaultPosture{
					FileAction:         fp,
					NetworkAction:      np,
					CapabilitiesAction: cp,
				}
				annotated := fa || na || ca
				// Set Visibility to Global Default
				visibility := tp.Visibility{
					File:         dm.validateVisibility("file", cfg.GlobalCfg.Visibility),
					Process:      dm.validateVisibility("process", cfg.GlobalCfg.Visibility),
					Network:      dm.validateVisibility("network", cfg.GlobalCfg.Visibility),
					Capabilities: dm.validateVisibility("capabilities", cfg.GlobalCfg.Visibility),
					DNS:          dm.validateVisibility("dns", cfg.GlobalCfg.Visibility),
					IMA:          dm.validateVisibility("ima", cfg.GlobalCfg.Visibility),
				}

				// Set Visibility to Namespace Annotation if exists
				if ns.Annotations != nil && ns.Annotations[visibilityKey] != "" {
					visibility = tp.Visibility{
						File:         dm.validateVisibility("file", ns.Annotations[visibilityKey]),
						Process:      dm.validateVisibility("process", ns.Annotations[visibilityKey]),
						Network:      dm.validateVisibility("network", ns.Annotations[visibilityKey]),
						Capabilities: dm.validateVisibility("capabilities", ns.Annotations[visibilityKey]),
						DNS:          dm.validateVisibility("dns", ns.Annotations[visibilityKey]),
						IMA:          dm.validateVisibility("ima", ns.Annotations[visibilityKey]),
					}
				}
				dm.UpdateDefaultPosture(addEvent, ns.Name, defaultPosture, annotated)
				dm.UpdateVisibility(addEvent, ns.Name, visibility)
			}
		},
		UpdateFunc: func(_, new any) {
			if ns, ok := new.(*corev1.Namespace); ok {
				fp, fa := validateDefaultPosture("kubearmor-file-posture", ns, cfg.GlobalCfg.DefaultFilePosture)
				np, na := validateDefaultPosture("kubearmor-network-posture", ns, cfg.GlobalCfg.DefaultNetworkPosture)
				cp, ca := validateDefaultPosture("kubearmor-capabilities-posture", ns, cfg.GlobalCfg.DefaultCapabilitiesPosture)
				defaultPosture := tp.DefaultPosture{
					FileAction:         fp,
					NetworkAction:      np,
					CapabilitiesAction: cp,
				}
				annotated := fa || na || ca
				// Set Visibility to Global Default
				visibility := tp.Visibility{
					File:         dm.validateVisibility("file", cfg.GlobalCfg.Visibility),
					Process:      dm.validateVisibility("process", cfg.GlobalCfg.Visibility),
					Network:      dm.validateVisibility("network", cfg.GlobalCfg.Visibility),
					Capabilities: dm.validateVisibility("capabilities", cfg.GlobalCfg.Visibility),
					DNS:          dm.validateVisibility("dns", cfg.GlobalCfg.Visibility),
					IMA:          dm.validateVisibility("ima", cfg.GlobalCfg.Visibility),
				}

				// Set Visibility to Namespace Annotation if exists
				if ns.Annotations != nil && ns.Annotations[visibilityKey] != "" {
					visibility = tp.Visibility{
						File:         dm.validateVisibility("file", ns.Annotations[visibilityKey]),
						Process:      dm.validateVisibility("process", ns.Annotations[visibilityKey]),
						Network:      dm.validateVisibility("network", ns.Annotations[visibilityKey]),
						Capabilities: dm.validateVisibility("capabilities", ns.Annotations[visibilityKey]),
						DNS:          dm.validateVisibility("dns", ns.Annotations[visibilityKey]),
						IMA:          dm.validateVisibility("ima", ns.Annotations[visibilityKey]),
					}
				}
				dm.UpdateDefaultPosture(updateEvent, ns.Name, defaultPosture, annotated)
				dm.UpdateVisibility(updateEvent, ns.Name, visibility)

			}
		},
		DeleteFunc: func(obj any) {
			if ns, ok := obj.(*corev1.Namespace); ok {
				_, fa := validateDefaultPosture("kubearmor-file-posture", ns, cfg.GlobalCfg.DefaultFilePosture)
				_, na := validateDefaultPosture("kubearmor-network-posture", ns, cfg.GlobalCfg.DefaultNetworkPosture)
				_, ca := validateDefaultPosture("kubearmor-capabilities-posture", ns, cfg.GlobalCfg.DefaultCapabilitiesPosture)
				annotated := fa || na || ca
				dm.UpdateDefaultPosture(deleteEvent, ns.Name, tp.DefaultPosture{}, annotated)
				dm.UpdateVisibility(deleteEvent, ns.Name, tp.Visibility{})
			}
		},
	})
	if err != nil {
		dm.Logger.Err("Couldn't start watching Default Posture Annotations and namespace")
		return nil
	}

	go factory.Start(StopChan)
	return registration.HasSynced
}

// WatchConfigMap function
func (dm *KubeArmorDaemon) WatchConfigMap() cache.InformerSynced {
	configMapLabelOption := informers.WithTweakListOptions(func(opts *metav1.ListOptions) {
		opts.LabelSelector = fmt.Sprintf("kubearmor-app=%s", "kubearmor-configmap")
	})
	factory := informers.NewSharedInformerFactoryWithOptions(K8s.K8sClient, 0, configMapLabelOption)
	informer := factory.Core().V1().ConfigMaps().Informer()

	cmNS := dm.GetConfigMapNS()

	var err error
	registration, err := informer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj any) {
			if cm, ok := obj.(*corev1.ConfigMap); ok && cm.Namespace == cmNS {
				cfg.GlobalCfg.HostVisibility = cm.Data[cfg.ConfigHostVisibility]
				cfg.GlobalCfg.Visibility = cm.Data[cfg.ConfigVisibility]
				cfg.GlobalCfg.Cluster = cm.Data[cfg.ConfigCluster]
				cfg.GlobalCfg.DropResourceFromProcessLogs = (cm.Data[cfg.ConfigDropResourceFromProcessLogs] == "true")
				dm.NodeLock.Lock()
				dm.Node.ClusterName = cm.Data[cfg.ConfigCluster]
				dm.NodeLock.Unlock()
				if v, ok := cm.Data[cfg.ConfigUntrackedNs]; ok {
					UpdateUntrackedNamespaces(v)
				}
				if _, ok := cm.Data[cfg.ConfigDefaultPostureLogs]; ok {
					cfg.GlobalCfg.DefaultPostureLogs = (cm.Data[cfg.ConfigDefaultPostureLogs] == "true")
				}
				globalPosture := tp.DefaultPosture{
					FileAction:         cm.Data[cfg.ConfigDefaultFilePosture],
					NetworkAction:      cm.Data[cfg.ConfigDefaultNetworkPosture],
					CapabilitiesAction: cm.Data[cfg.ConfigDefaultCapabilitiesPosture],
					DeviceAction:       cm.Data[cfg.ConfigHostDefaultDevicePosture],
				}
				currentGlobalPosture := tp.DefaultPosture{
					FileAction:         cfg.GlobalCfg.DefaultFilePosture,
					NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
					CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
					DeviceAction:       cfg.GlobalCfg.HostDefaultDevicePosture,
				}
				if _, ok := cm.Data[cfg.ConfigAlertThrottling]; ok {
					cfg.GlobalCfg.AlertThrottling = (cm.Data[cfg.ConfigAlertThrottling] == "true")
				}
				if _, ok := cm.Data[cfg.ConfigMaxAlertPerSec]; ok {
					maxAlertPerSec, err := strconv.ParseInt(cm.Data[cfg.ConfigMaxAlertPerSec], 10, 32)
					if err != nil {
						dm.Logger.Warnf("Error: %s", err)
					}
					cfg.GlobalCfg.MaxAlertPerSec = int32(maxAlertPerSec)
				}
				if _, ok := cm.Data[cfg.ConfigThrottleSec]; ok {
					throttleSec, err := strconv.ParseInt(cm.Data[cfg.ConfigThrottleSec], 10, 32)
					if err != nil {
						dm.Logger.Warnf("Error: %s", err)
					}
					cfg.GlobalCfg.ThrottleSec = int32(throttleSec)
				}
				if _, ok := cm.Data[cfg.ConfigEnableIma]; ok {
					enableIMA, err := strconv.ParseBool(cm.Data[cfg.ConfigEnableIma])
					if err != nil {
						dm.Logger.Warnf("Error parsing IMA config: %s", err)
					} else {
						cfg.GlobalCfg.EnableIMA = enableIMA
					}
				}
				dm.UpdateIMA(cfg.GlobalCfg.EnableIMA)
				dm.UpdateUSBDeviceHandler(cfg.GlobalCfg.USBDeviceHandler)
				dm.SystemMonitor.UpdateThrottlingConfig()

				dm.Logger.Printf("Current Global Posture is %v", currentGlobalPosture)
				dm.UpdateGlobalPosture(globalPosture)

				// update default posture for endpoints
				dm.updatEndpointsWithCM(cm, addEvent)
				// update visibility for namespaces
				dm.updateVisibilityWithCM(cm, addEvent)
			}
		},
		UpdateFunc: func(oldObj, newObj any) {
			if cm, ok := newObj.(*corev1.ConfigMap); ok && cm.Namespace == cmNS {
				cfg.GlobalCfg.HostVisibility = cm.Data[cfg.ConfigHostVisibility]
				cfg.GlobalCfg.Visibility = cm.Data[cfg.ConfigVisibility]

				cfg.GlobalCfg.Cluster = cm.Data[cfg.ConfigCluster]
				cfg.GlobalCfg.DropResourceFromProcessLogs = (cm.Data[cfg.ConfigDropResourceFromProcessLogs] == "true")
				dm.Node.ClusterName = cm.Data[cfg.ConfigCluster]
				if _, ok := cm.Data[cfg.ConfigDefaultPostureLogs]; ok {
					cfg.GlobalCfg.DefaultPostureLogs = (cm.Data[cfg.ConfigDefaultPostureLogs] == "true")
				}
				globalPosture := tp.DefaultPosture{
					FileAction:         cm.Data[cfg.ConfigDefaultFilePosture],
					NetworkAction:      cm.Data[cfg.ConfigDefaultNetworkPosture],
					CapabilitiesAction: cm.Data[cfg.ConfigDefaultCapabilitiesPosture],
				}
				currentGlobalPosture := tp.DefaultPosture{
					FileAction:         cfg.GlobalCfg.DefaultFilePosture,
					NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
					CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
				}
				dm.Logger.Printf("Current Global Posture is %v", currentGlobalPosture)
				dm.UpdateGlobalPosture(globalPosture)

				// update default posture for endpoints
				dm.updatEndpointsWithCM(cm, updateEvent)

				// forward untracked namespaces to SystemMonitor
				if v, ok := cm.Data[cfg.ConfigUntrackedNs]; ok {
					UpdateUntrackedNamespaces(v)
				}

				// visibility updates are already handled here
				dm.updateVisibilityWithCM(cm, updateEvent)

				if _, ok := cm.Data[cfg.ConfigAlertThrottling]; ok {
					cfg.GlobalCfg.AlertThrottling = (cm.Data[cfg.ConfigAlertThrottling] == "true")
				}

				maxAlertPerSec, err := strconv.ParseInt(cm.Data[cfg.ConfigMaxAlertPerSec], 10, 32)
				if err != nil {
					dm.Logger.Warnf("Error: %s", err)
				}
				cfg.GlobalCfg.MaxAlertPerSec = int32(maxAlertPerSec)

				throttleSec, err := strconv.ParseInt(cm.Data[cfg.ConfigThrottleSec], 10, 32)
				if err != nil {
					dm.Logger.Warnf("Error: %s", err)
				}
				cfg.GlobalCfg.ThrottleSec = int32(throttleSec)
				dm.SystemMonitor.UpdateThrottlingConfig()

				if _, ok := cm.Data[cfg.ConfigEnableIma]; ok {
					enableIMA, err := strconv.ParseBool(cm.Data[cfg.ConfigEnableIma])
					if err != nil {
						dm.Logger.Warnf("Error parsing IMA config: %s", err)
					} else {
						cfg.GlobalCfg.EnableIMA = enableIMA
					}
				}
				dm.UpdateIMA(cfg.GlobalCfg.EnableIMA)
				dm.UpdateUSBDeviceHandler(cfg.GlobalCfg.USBDeviceHandler)
			}
		},
		DeleteFunc: func(obj any) {
			// nothing to do here
		},
	})
	if err != nil {
		dm.Logger.Err("Couldn't start watching Configmap")
		return nil
	}

	go factory.Start(StopChan)
	return registration.HasSynced
}

// UpdateIMA func updates the status of IMA module
func (dm *KubeArmorDaemon) UpdateIMA(enabled bool) {
	if enabled && dm.SystemMonitor.ImaHash == nil {
		if err := dm.SystemMonitor.InitImaHash(); err != nil {
			dm.Logger.Warnf("error initializing IMA module: %s", err)
			return
		}
		dm.Logger.Print("Successfully initialized IMA module")
		return
	}
	if !enabled && dm.SystemMonitor.ImaHash != nil {
		if err := dm.SystemMonitor.ImaHash.DestroyImaHash(); err != nil {
			dm.Logger.Warnf("error uninitializing IMA module: %s", err)
			return
		}
		dm.SystemMonitor.ImaHash = nil
		dm.Logger.Print("Successfully uninitialized IMA module")
		return
	}
}

// UpdateUSBDeviceHandler updates the status of USB Device Handler
func (dm *KubeArmorDaemon) UpdateUSBDeviceHandler(enabled bool) {
	if enabled && dm.USBDeviceHandler == nil {
		if !dm.InitUSBDeviceHandler() {
			dm.Logger.Warn("Failed to initialize KubeArmor USB Device Handler")
			return
		}
		dm.Logger.Print("Initialized KubeArmor USB Device Handler")
		return
	}
	if !enabled && dm.USBDeviceHandler != nil {
		if !dm.CloseUSBDeviceHandler() {
			return
		}
		dm.Logger.Print("Closed KubeArmor USB Device Handler")
		return
	}
}

// GetConfigMapNS Returns KubeArmor configmap namespace
func (dm *KubeArmorDaemon) GetConfigMapNS() string {
	// get namespace from env
	envNamespace := os.Getenv("KUBEARMOR_NAMESPACE")

	if envNamespace == "" {
		// kubearmor is running as system process,
		// return "kubearmor" for testing purpose in dev env
		return "kubearmor"
	}
	return envNamespace
}

// UpdateUntrackedNamespaces updates the runtime untracked namespaces list.
func UpdateUntrackedNamespaces(v string) {
	parts := strings.Split(v, ",")

	namespaces := make([]string, 0, len(parts))
	for _, ns := range parts {
		if ns = strings.TrimSpace(ns); ns != "" {
			namespaces = append(namespaces, ns)
		}
	}
	cfg.GlobalCfg.ConfigUntrackedNs.Store(namespaces)
}
