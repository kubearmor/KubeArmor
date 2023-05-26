// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ==================== //
// == Docker Handler == //
// ==================== //

// Docker Handler
var Docker *DockerHandler

// DockerVersion Structure
type DockerVersion struct {
	APIVersion string `json:"ApiVersion"`
}

// DockerHandler Structure
type DockerHandler struct {
	DockerClient *client.Client
	Version      DockerVersion
}

// NewDockerHandler Function
func NewDockerHandler() (*DockerHandler, error) {
	docker := &DockerHandler{}

	// try to create a new docker client
	// If env DOCKER_API_VERSION set - NegotiateAPIVersion() won't do anything
	DockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil, err
	}
	DockerClient.NegotiateAPIVersion(context.Background())
	clientVersion := DockerClient.ClientVersion()

	kg.Printf("Verifying Docker API client version: %s", clientVersion)

	serverVersion, err := DockerClient.ServerVersion(context.Background())
	if err != nil {
		return nil, err
	}

	if clientVersion != serverVersion.APIVersion {
		kg.Warnf("Docker client (%s) and Docker server (%s) API versions don't match", clientVersion, serverVersion.APIVersion)
	}

	docker.DockerClient = DockerClient

	kg.Printf("Initialized Docker Handler (version: %s)", clientVersion)

	return docker, nil
}

// Close Function
func (dh *DockerHandler) Close() {
	if dh.DockerClient != nil {
		if err := dh.DockerClient.Close(); err != nil {
			kg.Err(err.Error())
		}
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function
func (dh *DockerHandler) GetContainerInfo(containerID string) (tp.Container, error) {
	if dh.DockerClient == nil {
		return tp.Container{}, errors.New("no docker client")
	}

	inspect, err := dh.DockerClient.ContainerInspect(context.Background(), containerID)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = inspect.ID
	container.ContainerName = strings.TrimLeft(inspect.Name, "/")

	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	containerLabels := inspect.Config.Labels
	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok { // kubernetes
		if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
			container.NamespaceName = val
		}
		if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
			container.EndPointName = val
		}
	}

	container.AppArmorProfile = inspect.AppArmorProfile

	container.MergedDir = inspect.GraphDriver.Data["MergedDir"]

	// == //

	pid := strconv.Itoa(inspect.State.Pid)

	if data, err := os.Readlink("/proc/" + pid + "/ns/pid"); err == nil {
		if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.PidNS); err != nil {
			kg.Warnf("Unable to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	}

	if data, err := os.Readlink("/proc/" + pid + "/ns/mnt"); err == nil {
		if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.MntNS); err != nil {
			kg.Warnf("Unable to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	}

	// == //

	return container, nil
}

// ========================== //
// == Docker Event Channel == //
// ========================== //

// GetEventChannel Function
func (dh *DockerHandler) GetEventChannel() <-chan events.Message {
	if dh.DockerClient != nil {
		event, _ := dh.DockerClient.Events(context.Background(), types.EventsOptions{})
		return event
	}

	return nil
}

// =================== //
// == Docker Events == //
// =================== //

// SetContainerVisibility function enables visibility flag arguments for un-orchestrated container
func (dm *KubeArmorDaemon) SetContainerVisibility(containerID string) {

	// get container information from docker client
	container, err := Docker.GetContainerInfo(containerID)
	if err != nil {
		return
	}

	if strings.Contains(cfg.GlobalCfg.Visibility, "process") {
		container.ProcessVisibilityEnabled = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "file") {
		container.FileVisibilityEnabled = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "network") {
		container.NetworkVisibilityEnabled = true
	}
	if strings.Contains(cfg.GlobalCfg.Visibility, "capabilities") {
		container.CapabilitiesVisibilityEnabled = true
	}

	container.EndPointName = container.ContainerName
	container.NamespaceName = "container_namespace"

	dm.Containers[container.ContainerID] = container
}

// GetAlreadyDeployedDockerContainers Function
func (dm *KubeArmorDaemon) GetAlreadyDeployedDockerContainers() {
	// check if Docker exists else instantiate
	if Docker == nil {
		var err error
		Docker, err = NewDockerHandler()
		if err != nil {
			dm.Logger.Errf("Failed to create new Docker client: %s", err)
		}
	}

	if containerList, err := Docker.DockerClient.ContainerList(context.Background(), types.ContainerListOptions{}); err == nil {
		for _, dcontainer := range containerList {
			// get container information from docker client
			container, err := Docker.GetContainerInfo(dcontainer.ID)
			if err != nil {
				continue
			}

			if container.ContainerID == "" {
				continue
			}
			if dcontainer.State == "running" {
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

							// update apparmor profiles
							if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
								dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
							}

							break
						}
					}
					dm.EndPointsLock.Unlock()
				} else {
					dm.ContainersLock.Unlock()
					continue
				}

				// check for unorchestrated docker containers
				if !dm.K8sEnabled {
					dm.ContainersLock.Lock()
					dm.SetContainerVisibility(dcontainer.ID)
					container = dm.Containers[dcontainer.ID]
					dm.ContainersLock.Unlock()
				}

				if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
					// update NsMap
					dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
					dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
				}

				dm.Logger.Printf("Detected a container (added/%.12s)", container.ContainerID)
			}
		}
	} else {
		dm.Logger.Warnf("Error while listing containers: %s", err)
	}
}

// UpdateDockerContainer Function
func (dm *KubeArmorDaemon) UpdateDockerContainer(containerID, action string) {
	// check if Docker exists
	if Docker == nil {
		return
	}

	container := tp.Container{}

	if action == "start" {
		var err error

		// get container information from docker client
		container, err = Docker.GetContainerInfo(containerID)
		if err != nil {
			return
		}

		if container.ContainerID == "" {
			return
		}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[containerID]; !ok {
			dm.Containers[containerID] = container
			dm.ContainersLock.Unlock()
		} else if dm.Containers[containerID].PidNS == 0 && dm.Containers[containerID].MntNS == 0 {
			// this entry was updated by kubernetes before docker detects it
			// thus, we here use the info given by kubernetes instead of the info given by docker

			container.NamespaceName = dm.Containers[containerID].NamespaceName
			container.EndPointName = dm.Containers[containerID].EndPointName
			container.Labels = dm.Containers[containerID].Labels

			container.ContainerName = dm.Containers[containerID].ContainerName
			container.ContainerImage = dm.Containers[containerID].ContainerImage

			container.PolicyEnabled = dm.Containers[containerID].PolicyEnabled

			container.ProcessVisibilityEnabled = dm.Containers[containerID].ProcessVisibilityEnabled
			container.FileVisibilityEnabled = dm.Containers[containerID].FileVisibilityEnabled
			container.NetworkVisibilityEnabled = dm.Containers[containerID].NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = dm.Containers[containerID].CapabilitiesVisibilityEnabled

			dm.Containers[containerID] = container
			dm.ContainersLock.Unlock()

			dm.EndPointsLock.Lock()
			for idx, endPoint := range dm.EndPoints {
				if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName && kl.ContainsElement(endPoint.Containers, container.ContainerID) {

					// update apparmor profiles
					if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
						dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
					}

					break
				}
			}
			dm.EndPointsLock.Unlock()
		} else {
			dm.ContainersLock.Unlock()
			return
		}

		if !dm.K8sEnabled {
			dm.ContainersLock.Lock()
			dm.SetContainerVisibility(containerID)
			container = dm.Containers[containerID]
			dm.ContainersLock.Unlock()
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(containerID, container.PidNS, container.MntNS)
		}

		if !dm.K8sEnabled {
			dm.ContainersLock.Lock()
			dm.EndPointsLock.Lock()
			dm.MatchandUpdateContainerSecurityPolicies(containerID)
			dm.EndPointsLock.Unlock()
			dm.ContainersLock.Unlock()
		}

		dm.Logger.Printf("Detected a container (added/%.12s)", containerID)

	} else if action == "stop" || action == "destroy" {
		// case 1: kill -> die -> stop
		// case 2: kill -> die -> destroy
		// case 3: destroy

		if !dm.K8sEnabled {
			dm.ContainersLock.Lock()
			dm.EndPointsLock.Lock()
			dm.MatchandRemoveContainerFromEndpoint(containerID)
			dm.EndPointsLock.Unlock()
			dm.ContainersLock.Unlock()
		}

		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
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

		dm.Logger.Printf("Detected a container (removed/%.12s)", containerID)
	}
}

// MonitorDockerEvents Function
func (dm *KubeArmorDaemon) MonitorDockerEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	// check if Docker exists else instantiate
	if Docker == nil {
		var err error
		Docker, err = NewDockerHandler()
		if err != nil {
			dm.Logger.Errf("Failed to create new Docker client: %s", err)
		}
	}

	dm.Logger.Print("Started to monitor Docker events")

	EventChan := Docker.GetEventChannel()

	for {
		select {
		case <-StopChan:
			return

		case msg, valid := <-EventChan:
			if !valid {
				continue
			}

			// if message type is container
			if msg.Type == "container" {
				dm.UpdateDockerContainer(msg.ID, msg.Action)
			}
		}
	}
}
