// SPDX-License-Identifier: Apache-2.0
// Copyright 2026  Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ListenToNonK8sHook starts listening on a UNIX socket and waits for container hooks
// to pass new containers
func (dm *KubeArmorDaemon) ListenToNonK8sHook() {
	dm.Logger.Print("Started to monitor non k8s hook events")

	if err := os.MkdirAll(kubearmorDir, 0750); err != nil {
		dm.Logger.Warnf("Failed to create ka.sock dir: %v", err)
	}

	listenPath := filepath.Join(kubearmorDir, "ka.sock")
	err := os.Remove(listenPath) // in case kubearmor crashed and the socket wasn't removed (cleaning the socket file if got crashed)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		dm.Logger.Warnf("Failed to cleanup ka.sock: %v", err)
	}

	socket, err := net.Listen("unix", listenPath)
	if err != nil {
		dm.Logger.Warnf("Failed listening on ka.sock: %v", err)
		return
	}

	// #nosec G302 Set the permissions of ka.sock to 777 so that rootless podman with user level priviledges can also communicate with the socket
	if err := os.Chmod(listenPath, 0777); err != nil {
		dm.Logger.Warnf("Failed to set permissions on %s: %v", listenPath, err)
	}

	defer socket.Close()
	defer os.Remove(listenPath)
	ready := &atomic.Bool{}

	for {
		conn, err := socket.Accept()
		if err != nil {
			dm.Logger.Warnf("Error accepting socket connection: %v", err)
		} else {
			go dm.handleNonK8sConn(conn, ready)
		}
	}

}

// handleNonK8sConn gets container details from container hooks.
func (dm *KubeArmorDaemon) handleNonK8sConn(conn net.Conn, ready *atomic.Bool) {
	// We need to makes sure that no containers accepted until all containers created before KubeArmor
	// are sent first. This is done mainly to avoid race conditions between hooks sending in
	// data that some containers were deleted only for process responsible for sending previous containers
	// to send that these containers are created. Which will leave KubeArmor in an incorrect state.
	defer conn.Close()
	buf := make([]byte, 4096)

	for {
		n, err := conn.Read(buf)
		if err == io.EOF {
			return
		} else if err != nil {
			dm.Logger.Warnf("Error reading connection: %v", err)
		}

		data := tp.HookRequest{}

		err = json.Unmarshal(buf[:n], &data)
		if err != nil {
			dm.Logger.Warnf("Error unmarshalling: %v", err)
		}

		if data.Detached {
			// we want KubeArmor to start accepting containers after
			// all previous container are set
			defer ready.Store(true)
		} else if !ready.Load() {
			_, err = conn.Write([]byte("err"))
			if err == io.EOF {
				return
			} else if err != nil {
				log.Println(err)
				return
			}
			continue
		}
		_, err = conn.Write([]byte("ok"))
		if err == io.EOF {
			return
		} else if err != nil {
			log.Println(err)
			return
		}

		// Handle the container create or delete event
		if data.Operation == tp.HookContainerCreate {
			if err := dm.UpdateContainer(data.Container.ContainerID, data.Container, "create"); err != nil {
				log.Printf("Failed to create container %s: %s", data.Container.ContainerID, err.Error())
			}
		} else {
			if err := dm.UpdateContainer(data.Container.ContainerID, data.Container, "destroy"); err != nil {
				log.Printf("Failed to destroy container %s: %s", data.Container.ContainerID, err.Error())
			}
		}

	}
}

// UpdateContainer Function
func (dm *KubeArmorDaemon) UpdateContainer(containerID string, container tp.Container, action string) error {

	if action == "create" {

		if container.ContainerID == "" {
			return fmt.Errorf("container ID is empty")
		}

		endPoint := tp.EndPoint{}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()

			containerLabels, containerIdentities := common.GetLabelsFromString(container.Labels)

			endPoint.EndPointName = container.ContainerName
			endPoint.ContainerName = container.ContainerName
			endPoint.NamespaceName = container.NamespaceName
			endPoint.Containers = []string{container.ContainerID}
			endPoint.Labels = containerLabels
			endPoint.Identities = containerIdentities
			endPoint.PolicyEnabled = tp.KubeArmorPolicyEnabled
			endPoint.ProcessVisibilityEnabled = true
			endPoint.FileVisibilityEnabled = true
			endPoint.NetworkVisibilityEnabled = true
			endPoint.CapabilitiesVisibilityEnabled = true

			endPoint.AppArmorProfiles = []string{"kubearmor_" + container.ContainerName}

			globalDefaultPosture := tp.DefaultPosture{
				FileAction:         cfg.GlobalCfg.DefaultFilePosture,
				NetworkAction:      cfg.GlobalCfg.DefaultNetworkPosture,
				CapabilitiesAction: cfg.GlobalCfg.DefaultCapabilitiesPosture,
			}
			endPoint.DefaultPosture = globalDefaultPosture

			dm.SecurityPoliciesLock.RLock()
			for _, secPol := range dm.SecurityPolicies {
				if kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) {
					endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPol)
				}
			}
			dm.SecurityPoliciesLock.RUnlock()

			dm.EndPointsLock.Lock()
			dm.EndPoints = append(dm.EndPoints, endPoint)
			dm.EndPointsLock.Unlock()

		} else {
			dm.ContainersLock.Unlock()
			return fmt.Errorf("container already exists")
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// for throttling
			dm.SystemMonitor.Logger.ContainerNsKey[containerID] = common.OuterKey{
				MntNs: container.MntNS,
				PidNs: container.PidNS,
			}

			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(containerID, container.PidNS, container.MntNS)

			if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endPoint yet
				dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
				if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					dm.Logger.Printf("Enforcing security policies for container ID %s", containerID)
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
				}
			}
		}

		if cfg.GlobalCfg.StateAgent {
			container.Status = "running"
			go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
		}

		dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)

	} else if action == "destroy" {
		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return fmt.Errorf("container not found for removal: %s", containerID)
		}
		dm.EndPointsLock.Lock()
		dm.MatchandRemoveContainerFromEndpoint(containerID)
		dm.EndPointsLock.Unlock()
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

		dm.EndPointsLock.Lock()
		// remove apparmor profile for that endpoint
		for idx, endPoint := range dm.EndPoints {
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				for idxA, profile := range endPoint.AppArmorProfiles {
					if profile == container.AppArmorProfile {
						dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles[:idxA], dm.EndPoints[idx].AppArmorProfiles[idxA+1:]...)
						break
					}
				}

				break
			}
		}
		dm.EndPointsLock.Unlock()
		// delete endpoint if no security rules and containers
		idx := 0
		endpointsLength := len(dm.EndPoints)
		for idx < endpointsLength {
			endpoint := dm.EndPoints[idx]
			if container.NamespaceName == endpoint.NamespaceName && container.ContainerName == endpoint.EndPointName &&
				len(endpoint.SecurityPolicies) == 0 && len(endpoint.Containers) == 0 {
				dm.EndPoints = append(dm.EndPoints[:idx], dm.EndPoints[idx+1:]...)
				endpointsLength--
				idx--
			}
			idx++
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			outkey := dm.SystemMonitor.Logger.ContainerNsKey[containerID]
			dm.Logger.DeleteAlertMapKey(outkey)
			delete(dm.SystemMonitor.Logger.ContainerNsKey, containerID)
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
		}

		if cfg.GlobalCfg.StateAgent {
			container.Status = "terminated"
			go dm.StateAgent.PushContainerEvent(container, state.EventDeleted)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)
	}

	return nil
}
