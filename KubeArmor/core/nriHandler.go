// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"fmt"
	"os"

	"github.com/containerd/nri/pkg/api"
	"github.com/containerd/nri/pkg/stub"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
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

	containersByNamespaces map[namespaceKey]string

	handleDeletedContainer func(tp.Container)
	handleNewContainer     func(tp.Container)
}

// NewNRIHandler creates a new NRIHandler with the given event callbacks.
func NewNRIHandler(
	handleDeletedContainer func(tp.Container),
	handleNewContainer func(tp.Container),
) *NRIHandler {
	nri := &NRIHandler{}

	opts := []stub.Option{
		stub.WithSocketPath(cfg.GlobalCfg.NRISocket),
		stub.WithPluginIdx(cfg.GlobalCfg.NRIIndex),
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
		container := nriToKubeArmorContainer(nriContainer)
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
	container := nriToKubeArmorContainer(nriContainer)
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
	container := nriToKubeArmorContainer(nriContainer)
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
	container := nriToKubeArmorContainer(nriContainer)
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
func nriToKubeArmorContainer(nriContainer *api.Container) tp.Container {
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

	// TODO: Not sure how to get the apparmor profile from NRI

	// Read PID and mount namespaces from container root PID
	if nriContainer.Pid != 0 {
		nsPath := fmt.Sprintf("/proc/%d/ns", nriContainer.Pid)

		if data, err := os.Readlink(nsPath + "/pid"); err == nil {
			if _, err := fmt.Sscanf(data, "pid:[%d]", &container.PidNS); err != nil {
				kg.Warnf("Unable to get PidNS (%s, %s, %s)", nriContainer.Id, nriContainer.Pid, err.Error())
			}
		}

		if data, err := os.Readlink(nsPath + "/mnt"); err == nil {
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

		// TODO: Can't update AppArmor profiles since we can't get them from NRI

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(container.ContainerID)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)
	}

	handleNewContainer := func(container tp.Container) {
		dm.ContainersLock.Lock()
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
					if !kl.ContainsElement(endPoint.Containers, container.ContainerID) {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
					}

					break
				}
			}
			dm.EndPointsLock.Unlock()
		} else {
			dm.ContainersLock.Unlock()
			return
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
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

	NRI = NewNRIHandler(handleDeletedContainer, handleNewContainer)

	// check if NRI exists
	if NRI == nil {
		return
	}

	NRI.Start()

	dm.Logger.Print("Started to monitor NRI events")
}
