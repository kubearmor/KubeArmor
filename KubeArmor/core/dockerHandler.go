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
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
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

	// needed for container info
	NodeIP string
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

	docker.NodeIP = kl.GetExternalIPAddr()

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
func (dh *DockerHandler) GetContainerInfo(containerID string, OwnerInfo map[string]tp.PodOwner) (tp.Container, error) {
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
	} else if val, ok := containerLabels["kubearmor.io/namespace"]; ok {
		container.NamespaceName = val
	} else {
		container.NamespaceName = "container_namespace"
	}

	if len(OwnerInfo) > 0 {
		if podOwnerInfo, ok := OwnerInfo[container.EndPointName]; ok {
			container.Owner = podOwnerInfo
		}
	}

	container.AppArmorProfile = inspect.AppArmorProfile
	fmt.Println("AppArmorProfile from docker handler for:", container.AppArmorProfile, container.ContainerName)
	if inspect.HostConfig.Privileged ||
		(inspect.HostConfig.CapAdd != nil && len(inspect.HostConfig.CapAdd) > 0) {
		container.Privileged = inspect.HostConfig.Privileged
	}

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

	if cfg.GlobalCfg.StateAgent && !cfg.GlobalCfg.K8sEnv {
		container.ContainerImage = inspect.Config.Image //+ kl.GetSHA256ofImage(inspect.Image)

		container.NodeName = cfg.GlobalCfg.Host

		labels := []string{}
		for k, v := range inspect.Config.Labels {
			labels = append(labels, k+"="+v)
		}

		if _, ok := containerLabels["kubearmor.io/container.name"]; !ok {
			labels = append(labels, "kubearmor.io/container.name="+container.ContainerName)
		}

		container.Labels = strings.Join(labels, ",")

		var podIP string
		if inspect.HostConfig.NetworkMode.IsNone() || inspect.HostConfig.NetworkMode.IsContainer() {
			podIP = ""
		} else if inspect.HostConfig.NetworkMode.IsHost() {
			podIP = dh.NodeIP
		} else if inspect.HostConfig.NetworkMode.IsDefault() {
			podIP = inspect.NetworkSettings.Networks["bridge"].IPAddress
		} else {
			networkName := inspect.HostConfig.NetworkMode.NetworkName()
			podIP = inspect.NetworkSettings.Networks[networkName].IPAddress
		}
		container.ContainerIP = podIP

		// time format used by docker engine is RFC3339Nano
		lastUpdatedAt, err := time.Parse(time.RFC3339Nano, inspect.State.StartedAt)
		if err == nil {
			container.LastUpdatedAt = lastUpdatedAt.UTC().String()
		}
		// finished at is IsZero until a container exits
		timeFinished, err := time.Parse(time.RFC3339Nano, inspect.State.FinishedAt)
		if err == nil && !timeFinished.IsZero() && timeFinished.After(lastUpdatedAt) {
			lastUpdatedAt = timeFinished
		}

	}

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
	container, err := Docker.GetContainerInfo(containerID, dm.OwnerInfo)
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
			container, err := Docker.GetContainerInfo(dcontainer.ID, dm.OwnerInfo)
			if err != nil {
				continue
			}

			if container.ContainerID == "" {
				continue
			}

			endpoint := tp.EndPoint{}

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

							if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
								dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
							}

							endpoint = dm.EndPoints[idx]

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

				if cfg.GlobalCfg.StateAgent {
					go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
				}

				if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
					// update NsMap
					dm.SystemMonitor.AddContainerIDToNsMap(container.ContainerID, container.NamespaceName, container.PidNS, container.MntNS)
					dm.RuntimeEnforcer.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)

					if len(endpoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
						dm.Logger.UpdateSecurityPolicies("ADDED", endpoint)
						if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
							// enforce security policies
							dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
						}
					}
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
		container, err = Docker.GetContainerInfo(containerID, dm.OwnerInfo)
		if err != nil {
			return
		}

		if container.ContainerID == "" {
			return
		}

		endpoint := tp.EndPoint{}

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
					fmt.Println("PID 0 CHECK APPARMOR PROFILE:", container.AppArmorProfile)
					if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
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

			if len(endpoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
				dm.Logger.UpdateSecurityPolicies("ADDED", endpoint)
				if dm.RuntimeEnforcer != nil && endpoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endpoint)
				}
			}
		}

		if !dm.K8sEnabled {
			dm.ContainersLock.Lock()
			dm.EndPointsLock.Lock()
			dm.MatchandUpdateContainerSecurityPolicies(containerID)
			dm.EndPointsLock.Unlock()
			dm.ContainersLock.Unlock()
		}

		if cfg.GlobalCfg.StateAgent {
			container.Status = "running"
			go dm.StateAgent.PushContainerEvent(container, state.EventAdded)
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

		if cfg.GlobalCfg.StateAgent {
			container.Status = "terminated"
			go dm.StateAgent.PushContainerEvent(container, state.EventDeleted)
		}

		if dm.SystemMonitor != nil && cfg.GlobalCfg.Policy {
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s)", containerID)
	} else if action == "die" && cfg.GlobalCfg.StateAgent {
		// handle die - keep map but update state
		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return
		}
		dm.ContainersLock.Unlock()

		container.Status = "waiting"
		go dm.StateAgent.PushContainerEvent(container, state.EventUpdated)
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
