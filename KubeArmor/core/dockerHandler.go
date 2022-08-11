// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"encoding/json"
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
func NewDockerHandler() *DockerHandler {
	docker := &DockerHandler{}

	// specify the docker api version that we want to use
	// Versioned API: https://docs.docker.com/engine/api/

	versionStr, err := kl.GetCommandOutputWithErr("curl", []string{"--silent", "--unix-socket", strings.TrimPrefix(cfg.GlobalCfg.CRISocket, "unix://"), "http://localhost/version"})
	if err != nil {
		return nil
	}

	if err := json.Unmarshal([]byte(versionStr), &docker.Version); err != nil {
		kg.Warnf("Unable to get Docker version (%s)", err.Error())
	}

	apiVersion, _ := strconv.ParseFloat(docker.Version.APIVersion, 64)

	if apiVersion >= 1.39 {
		// downgrade the api version to 1.39
		if err := os.Setenv("DOCKER_API_VERSION", "1.39"); err != nil {
			kg.Warnf("Unable to set DOCKER_API_VERSION (%s)", err.Error())
		}
	} else {
		// set the current api version
		if err := os.Setenv("DOCKER_API_VERSION", docker.Version.APIVersion); err != nil {
			kg.Warnf("Unable to set DOCKER_API_VERSION (%s)", err.Error())
		}
	}

	// create a new client with the above env variable

	DockerClient, err := client.NewClientWithOpts(client.FromEnv)
	if err != nil {
		return nil
	}
	docker.DockerClient = DockerClient

	kg.Printf("Initialized Docker Handler (version: %s)", docker.Version.APIVersion)

	return docker
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

// GetAlreadyDeployedDockerContainers Function
func (dm *KubeArmorDaemon) GetAlreadyDeployedDockerContainers() {
	// check if Docker exists else instantiate
	if Docker == nil {
		Docker = NewDockerHandler()
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
						if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName {
							// update containers
							if !kl.ContainsElement(endPoint.Containers, container.ContainerID) {
								dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
							}

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

				if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
					// update NsMap
					dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.PidNS, container.MntNS)
					dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
				}

				dm.Logger.Printf("Detected a container (added/%s)", container.ContainerID[:12])
			}
		}
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
				if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName {
					// update containers
					if !kl.ContainsElement(endPoint.Containers, container.ContainerID) {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
					}

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

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(containerID, container.PidNS, container.MntNS)
		}

		dm.Logger.Printf("Detected a container (added/%s)", containerID[:12])

	} else if action == "stop" || action == "destroy" {
		// case 1: kill -> die -> stop
		// case 2: kill -> die -> destroy
		// case 3: destroy

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
			if endPoint.NamespaceName == container.NamespaceName && endPoint.EndPointName == container.EndPointName {
				// update containers
				for idxC, containerID := range endPoint.Containers {
					if containerID == container.ContainerID {
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers[:idxC], dm.EndPoints[idx].Containers[idxC+1:]...)
						break
					}
				}

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
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID)
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
		}

		dm.Logger.Printf("Detected a container (removed/%s)", containerID[:12])
	}
}

// MonitorDockerEvents Function
func (dm *KubeArmorDaemon) MonitorDockerEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	// check if Docker exists else instantiate
	if Docker == nil {
		Docker = NewDockerHandler()
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
