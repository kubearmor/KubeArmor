// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// NRI Handler
var NRI *NRIHandler

type namespaceKey struct {
	PidNS uint32
	MntNS uint32
}

// namespaceKeyFromContainer creates a namespaceKey from a container.
func namespaceKeyFromContainer(container tp.Container) namespaceKey {
	return namespaceKey{
		PidNS: container.PidNS,
		MntNS: container.MntNS,
	}
}

// NRIHandler connects to an NRI socket and informs on container
// creation/deletion events.
type NRIHandler struct {
	// NRI plugin stub
	stub stub.Stub

	// active containers
	containers map[string]tp.Container

	dm *KubeArmorDaemon

	containersByNamespaces map[namespaceKey]string

	handleDeletedContainer func(tp.Container)
	handleNewContainer     func(tp.Container)
}

// NewNRIHandler creates a new NRIHandler with the given event callbacks.
func (dm *KubeArmorDaemon) NewNRIHandler(
	handleDeletedContainer func(tp.Container),
	handleNewContainer func(tp.Container),
) *NRIHandler {
	nri := &NRIHandler{dm: dm}

	opts := []stub.Option{
		stub.WithSocketPath(cfg.GlobalCfg.NRISocket),
		stub.WithPluginIdx(cfg.GlobalCfg.NRIIndex),
		stub.WithOnClose(func() {
			kg.Printf("restarting NRI")
			nri.Start()
		}),
	}

	stub, err := stub.New(nri, opts...)
	if err != nil {
		kg.Errf("Failed to create NRI stub: %s", err.Error())
		return nil
	}

	nri.containers = map[string]tp.Container{}
	nri.containersByNamespaces = map[namespaceKey]string{}
	nri.stub = stub
	nri.handleDeletedContainer = handleDeletedContainer
	nri.handleNewContainer = handleNewContainer

	return nri
}

// Start initiates a configured NRI connection.
func (nh *NRIHandler) Start() {
	go func() {
		err := nh.stub.Run(context.Background())
		if err != nil {
			kg.Errf("Failed to connect to NRI: %s", err.Error())
		}
	}()
}

// Stop closes the NRI connection.
func (nh *NRIHandler) Close() {
	nh.stub.Stop()
}

// Synchronize is an NRI callback which is called at the beginning of an NRI
// socket connection to inform on all existing containers.
func (nh *NRIHandler) Synchronize(
	_ context.Context,
	_ []*api.PodSandbox,
	nriContainers []*api.Container,
) ([]*api.ContainerUpdate, error) {
	for _, nriContainer := range nriContainers {
		container := nh.nriToKubeArmorContainer(nriContainer)
		container = nh.mergeContainer(container, false)

		// Overlapping namespace IDs between containers should be impossible
		// here
		namespaceKey := namespaceKeyFromContainer(container)
		nh.containersByNamespaces[namespaceKey] = container.ContainerID

		nh.handleNewContainer(container)
	}

	return nil, nil
}

// StartContainer is an NRI callback which is called after a container has
// started.
//
// Unfortunately we can't use the CreateContainer or PostCreateContainer NRI
// callbacks because they are called without a PID value, which is required in
// order to get the PID and mount namespaces of the container. This means that
// there is a short period of time between a container starting and us enforcing
// it.
//
// If StartContainer detects a container namespace ID overlap with a previous
// container (since Linux can reuse namespace IDs), it will override the old
// policy correctly, but any actions runc took to set up this container and
// start it will be logged/enforced as if they were the old container's actions.
// This should be exceedingly rare, but there's no way using just NRI that we
// can entirely avoid this scenario.
func (nh *NRIHandler) StartContainer(
	_ context.Context,
	_ *api.PodSandbox,
	nriContainer *api.Container,
) error {
	container := nh.nriToKubeArmorContainer(nriContainer)
	container = nh.mergeContainer(container, false)

	namespaceKey := namespaceKeyFromContainer(container)

	// It's technically possible for a container to crash and a new one to be
	// started, all before we receive the StopContainer event. And because Linux
	// can reuse namespace IDs, it's possible for the enforcement configuration
	// to get confused and messed up, so if namespace IDs ever overlap, we
	// assume the previous container using those namespaces has already exited.
	if oldContainerID, ok := nh.containersByNamespaces[namespaceKey]; ok {
		delete(nh.containers, container.ContainerID)

		nh.handleDeletedContainer(nh.containers[oldContainerID])
	}

	nh.containersByNamespaces[namespaceKey] = container.ContainerID

	nh.handleNewContainer(container)

	return nil
}

// StopContainer is an NRI callback which is called before a container receives
// the signal to stop.
//
// StopContainer is called synchronously before a termination signal is sent to
// a container, so we can be sure that we stop enforcing before the container
// shuts down, at least in most cases. This means that if a new container reuses
// Linux namespace IDs from a previous container, so long as that previous
// container didn't crash unexpectedly, we can be sure that we won't
// accidentally enforce the new container with the old container's policy.
//
// The tradeoff here is that once a container receives its termination signal,
// KubeArmor is no longer enforcing anything on it while it shuts down.
func (nh *NRIHandler) StopContainer(
	_ context.Context,
	_ *api.PodSandbox,
	nriContainer *api.Container,
) ([]*api.ContainerUpdate, error) {
	container := nh.nriToKubeArmorContainer(nriContainer)
	container = nh.mergeContainer(container, true)

	// Only handle the container deleted event if it wasn't already 'deleted' by
	// the StartContainer event (due to a Linux namespace ID collision).
	if _, ok := nh.containersByNamespaces[namespaceKeyFromContainer(container)]; ok {
		delete(nh.containers, container.ContainerID)

		nh.handleDeletedContainer(container)
	}

	return nil, nil
}

// RemoveContainer is an NRI callback which is called after a container has
// exited.
//
// In case StopContainer isn't called, we hook into RemoveContainer to ensure
// that we stop enforcing a container after it has exited. For example, the NRI
// API doesn't guarantee that StopContainer will be called if a container
// crashed unexpectedly.
func (nh *NRIHandler) RemoveContainer(
	_ context.Context,
	_ *api.PodSandbox,
	nriContainer *api.Container,
) ([]*api.ContainerUpdate, error) {
	container := nh.nriToKubeArmorContainer(nriContainer)
	container = nh.mergeContainer(container, true)

	// Only handle the container deleted event if it wasn't already 'deleted' by
	// the StartContainer event (due to a Linux namespace ID collision) or
	// StopContainer event.
	if _, ok := nh.containersByNamespaces[namespaceKeyFromContainer(container)]; ok {
		delete(nh.containers, container.ContainerID)

		nh.handleDeletedContainer(container)
	}

	return nil, nil
}

// mergeContainer updates the container with the container's previously-stored
// namespace IDs, if any, also storing namespaceIDs for future reference.
func (nh *NRIHandler) mergeContainer(container tp.Container, removing bool) tp.Container {
	if existing, ok := nh.containers[container.ContainerID]; ok {
		if existing.PidNS != 0 {
			container.PidNS = existing.PidNS
		}

		if existing.MntNS != 0 {
			container.MntNS = existing.MntNS
		}

		nh.containers[container.ContainerID] = container
	} else if !removing {
		nh.containers[container.ContainerID] = container
	}

	return container
}

// nriToKubeArmorContainer converts an NRI container to a KubeArmor container.
func (nh *NRIHandler) nriToKubeArmorContainer(nriContainer *api.Container) tp.Container {
	container := tp.Container{}

	container.ContainerID = nriContainer.Id
	container.ContainerName = nriContainer.Name

	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	if _, ok := nriContainer.Labels["io.kubernetes.pod.namespace"]; ok {
		container.NamespaceName = nriContainer.Labels["io.kubernetes.pod.namespace"] // Pod namespace

		if _, ok := nriContainer.Labels["io.kubernetes.pod.name"]; ok {
			container.EndPointName = nriContainer.Labels["io.kubernetes.pod.name"] // Pod name
		}
	}

	var podName string
	var podNamespace string

	if name, ok := nriContainer.Labels["io.kubernetes.pod.name"]; ok {
		podName = name
	}
	if namespace, ok := nriContainer.Labels["io.kubernetes.pod.namespace"]; ok {
		podNamespace = namespace
	}

	if nh.dm.K8sEnabled {
		pod, err := K8s.K8sClient.CoreV1().Pods(podNamespace).Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			kg.Warnf("failed to fetch Pod: %w\n", err)
		}

		if appArmorProfile, ok := pod.Annotations["container.apparmor.security.beta.kubernetes.io/"+nriContainer.Name]; ok {
			profile := strings.Split(appArmorProfile, "/")
			if len(profile) > 1 {
				container.AppArmorProfile = profile[1]
			}
		}
	} else {
		container.AppArmorProfile = "kubearmor_" + container.ContainerName
	}

	// Read PID and mount namespaces from container root PID
	if nriContainer.Pid != 0 {
		pid := strconv.Itoa(int(nriContainer.Pid))

		if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, pid, "/ns/pid")); err == nil {
			if _, err := fmt.Sscanf(data, "pid:[%d]", &container.PidNS); err != nil {
				kg.Warnf("Unable to get PidNS (%s, %s, %s)", nriContainer.Id, nriContainer.Pid, err.Error())
			}
		}

		if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, pid, "/ns/mnt")); err == nil {
			if _, err := fmt.Sscanf(data, "mnt:[%d]", &container.MntNS); err != nil {
				kg.Warnf("Unable to get MntNS (%s, %s, %s)", nriContainer.Id, nriContainer.Pid, err.Error())
			}
		}
	}

	return container
}

// MonitorNRIEvents monitors NRI events.
func (dm *KubeArmorDaemon) MonitorNRIEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	handleNewContainer := func(container tp.Container) {
		endpoint := tp.EndPoint{}

		dm.ContainersLock.Lock()

		if len(dm.OwnerInfo) > 0 {
			if podOwnerInfo, ok := dm.OwnerInfo[container.EndPointName]; ok {
				container.Owner = podOwnerInfo
			}
		}

		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()
		} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
			// this entry was updated by kubernetes before docker detects it
			// thus, we here use the info given by kubernetes instead of the info given by docker

			container.NamespaceName = dm.Containers[container.ContainerID].NamespaceName
			container.EndPointName = dm.Containers[container.ContainerID].EndPointName
			container.Labels = dm.Containers[container.ContainerID].Labels

			container.ContainerName = dm.Containers[container.ContainerID].ContainerName
			container.ContainerImage = dm.Containers[container.ContainerID].ContainerImage

			container.PolicyEnabled = dm.Containers[container.ContainerID].PolicyEnabled

			container.ProcessVisibilityEnabled = dm.Containers[container.ContainerID].ProcessVisibilityEnabled
			container.FileVisibilityEnabled = dm.Containers[container.ContainerID].FileVisibilityEnabled
			container.NetworkVisibilityEnabled = dm.Containers[container.ContainerID].NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = dm.Containers[container.ContainerID].CapabilitiesVisibilityEnabled

			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()

			dm.EndPointsLock.Lock()
			for idx, endPoint := range dm.EndPoints {
				if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {
					// update containers
					if !kl.ContainsElement(endPoint.Containers, container.ContainerID) { // does not make sense but need to verify
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
					}

					endpoint = dm.EndPoints[idx]

					break
				}
			}
			dm.EndPointsLock.Unlock()
		} else {
			dm.ContainersLock.Unlock()
			return
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// for throttling
			dm.SystemMonitor.Logger.ContainerNsKey[container.ContainerID] = common.OuterKey{
				MntNs: container.MntNS,
				PidNs: container.PidNS,
			}
			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
			if dm.Presets != nil {
				dm.Presets.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
			}

			if len(endpoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
				dm.Logger.UpdateSecurityPolicies("ADDED", endpoint)
				if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
				}
				if dm.Presets != nil && endpoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce preset rules
					dm.Presets.UpdateSecurityPolicies(endpoint)
				}
			}
		}

		if !dm.K8sEnabled {
			dm.ContainersLock.Lock()
			dm.EndPointsLock.Lock()
			dm.MatchandUpdateContainerSecurityPolicies(container.ContainerID)
			dm.EndPointsLock.Unlock()
			dm.ContainersLock.Unlock()
		}

		dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
	}

	handleDeletedContainer := func(container tp.Container) {
		dm.ContainersLock.Lock()
		_, ok := dm.Containers[container.ContainerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return
		}
		if !dm.K8sEnabled {
			dm.EndPointsLock.Lock()
			dm.MatchandRemoveContainerFromEndpoint(container.ContainerID)
			dm.EndPointsLock.Unlock()
		}
		delete(dm.Containers, container.ContainerID)
		dm.ContainersLock.Unlock()

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			outkey := dm.SystemMonitor.Logger.ContainerNsKey[container.ContainerID]
			dm.Logger.DeleteAlertMapKey(outkey)
			delete(dm.SystemMonitor.Logger.ContainerNsKey, container.ContainerID)
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(container.ContainerID)
			if dm.Presets != nil {
				dm.Presets.UnregisterContainer(container.ContainerID)
			}
		}

		dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
	}

	NRI = dm.NewNRIHandler(handleDeletedContainer, handleNewContainer)

	// check if NRI exists
	if NRI == nil {
		return
	}

	NRI.Start()

	dm.Logger.Print("Started to monitor NRI events")
}
