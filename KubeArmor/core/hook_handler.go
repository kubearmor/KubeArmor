// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package core

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
)

const kubearmorDir = "/var/run/kubearmor"

// ListenToHook starts listening on a UNIX socket and waits for container hooks
// to pass new containers
func (dm *KubeArmorDaemon) ListenToK8sHook() {
	dm.Logger.Print("Started to monitor OCI Hook events")
	if err := os.MkdirAll(kubearmorDir, 0750); err != nil {
		dm.Logger.Warnf("Failed to create ka.sock dir: %v", err)
	}

	listenPath := filepath.Join(kubearmorDir, "ka.sock")
	err := os.Remove(listenPath) // in case kubearmor crashed and the socket wasn't removed
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		dm.Logger.Warnf("Failed to cleanup ka.sock: %v", err)
	}

	socket, err := net.Listen("unix", listenPath)
	if err != nil {
		dm.Logger.Warnf("Failed listening on ka.sock: %v", err)
		return
	}

	defer socket.Close()
	defer os.Remove(listenPath)
	ready := &atomic.Bool{}

	for {
		conn, err := socket.Accept()
		if err != nil {
			dm.Logger.Warnf("Error accepting socket connection: %v", err)
		}

		go dm.handleK8sConn(conn, ready)
	}

}

// handleConn gets container details from container hooks.
func (dm *KubeArmorDaemon) handleK8sConn(conn net.Conn, ready *atomic.Bool) {
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

		data := types.HookRequest{}

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

		if data.Operation == types.HookContainerCreate {
			dm.handleContainerCreate(data.Container)
		} else {
			dm.handleContainerDelete(data.Container.ContainerID)
		}
	}
}
func (dm *KubeArmorDaemon) handleContainerCreate(container types.Container) {
	endpoint := types.EndPoint{}

	dm.Logger.Printf("Detected a container (added/%.12s/pidns=%d/mntns=%d)", container.ContainerID, container.PidNS, container.MntNS)

	dm.ContainersLock.Lock()
	defer dm.ContainersLock.Unlock()
	if _, ok := dm.Containers[container.ContainerID]; !ok {
		dm.Containers[container.ContainerID] = container
	} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
		c := dm.Containers[container.ContainerID]
		c.MntNS = container.MntNS
		c.PidNS = container.PidNS
		c.AppArmorProfile = container.AppArmorProfile
		dm.Containers[c.ContainerID] = c

		dm.EndPointsLock.Lock()
		for idx, endPoint := range dm.EndPoints {
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

				// update apparmor profiles
				if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
					// this path is expected to have a single componenet "apparmor-profile"
					// and this is to ensure that the filename has no path separators or parent directory references
					if strings.Contains(container.AppArmorProfile, "/") || strings.Contains(container.AppArmorProfile, "\\") || strings.Contains(container.AppArmorProfile, "..") {
						dm.Logger.Warnf("Invalid AppArmor profile name (%s)", container.AppArmorProfile)
						continue
					}
					dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
				}

				if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
					dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
				}

				endpoint = dm.EndPoints[idx]

				break
			}
		}
		dm.EndPointsLock.Unlock()
	}

	if len(dm.OwnerInfo) > 0 {
		dm.OwnerInfoLock.RLock()
		container.Owner = dm.OwnerInfo[container.EndPointName]
		dm.OwnerInfoLock.RUnlock()
	}

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
		dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)

		if len(endpoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
			dm.Logger.UpdateSecurityPolicies("ADDED", endpoint)
			if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == types.KubeArmorPolicyEnabled {
				// enforce security policies
				dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
			}
		}
	}
}
func (dm *KubeArmorDaemon) handleContainerDelete(containerID string) {
	dm.ContainersLock.Lock()
	container, ok := dm.Containers[containerID]
	dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)
	if !ok {
		dm.ContainersLock.Unlock()
		return
	}
	delete(dm.Containers, containerID)
	dm.ContainersLock.Unlock()

	dm.EndPointsLock.Lock()
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

	if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
		// update NsMap
		dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
		dm.RuntimeEnforcer.UnregisterContainer(containerID)
	}

}
