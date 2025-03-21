// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
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

	containerLabels := make(map[string]string)
	containerLabels = inspect.Config.Labels
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
	if inspect.HostConfig.Privileged ||
		(inspect.HostConfig.CapAdd != nil && len(inspect.HostConfig.CapAdd) > 0) {
		container.Privileged = inspect.HostConfig.Privileged
	}

	// == //

	pid := strconv.Itoa(inspect.State.Pid)

	if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, pid, "/ns/pid")); err == nil {
		if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.PidNS); err != nil {
			kg.Warnf("Unable to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	}

	if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, pid, "/ns/mnt")); err == nil {
		if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.MntNS); err != nil {
			kg.Warnf("Unable to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	}

	// == //

	if !cfg.GlobalCfg.K8sEnv {
		container.ContainerImage = inspect.Config.Image //+ kl.GetSHA256ofImage(inspect.Image)

		container.NodeName = cfg.GlobalCfg.Host

		labels := []string{}
		for k, v := range containerLabels {
			labels = append(labels, k+"="+v)
		}

		// for policy matching
		labels = append(labels, "namespaceName="+container.NamespaceName)
		if _, ok := containerLabels["kubearmor.io/container.name"]; !ok {
			labels = append(labels, "kubearmor.io/container.name="+container.ContainerName)
		}

		container.Labels = strings.Join(labels, ",")

		var podIP string
		if inspect.HostConfig != nil {
			if inspect.HostConfig.NetworkMode.IsNone() || inspect.HostConfig.NetworkMode.IsContainer() {
				podIP = ""
			} else if inspect.HostConfig.NetworkMode.IsHost() {
				podIP = dh.NodeIP
			} else {
				// user defined network OR swarm mode
				networkName := inspect.HostConfig.NetworkMode.NetworkName()
				networkInfo, ok := inspect.NetworkSettings.Networks[networkName]
				if ok && networkInfo != nil {
					podIP = networkInfo.IPAddress
				}
			}
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
func (dh *DockerHandler) GetEventChannel(ctx context.Context, StopChan <- chan struct{}) <-chan events.Message {
	if dh.DockerClient != nil {
		eventBuffer := make(chan events.Message, 256)

		go func() {

			eventStream, _ := dh.DockerClient.Events(ctx, events.ListOptions{})
			defer close(eventBuffer)

			for event := range eventStream {
				select {
				case eventBuffer <- event:
				case <-ctx.Done():
					return
				case <-StopChan:
					return
				default:
					kg.Warnf("Docker channel full.")
				}
			}
		}()

		return eventBuffer
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

	if containerList, err := Docker.DockerClient.ContainerList(context.Background(), container.ListOptions{}); err == nil {
		for _, dcontainer := range containerList {
			// get container information from docker client
			container, err := Docker.GetContainerInfo(dcontainer.ID, dm.OwnerInfo)
			if err != nil {
				continue
			}

			if container.ContainerID == "" {
				continue
			}

			endPoint := tp.EndPoint{}

			if dcontainer.State == "running" {
				dm.ContainersLock.Lock()
				if _, ok := dm.Containers[container.ContainerID]; !ok {
					dm.Containers[container.ContainerID] = container
					dm.ContainersLock.Unlock()

					// create/update endpoint in non-k8s mode
					if !dm.K8sEnabled {
						endPointEvent := "ADDED"
						endPointIdx := -1

						containerLabels, containerIdentities := common.GetLabelsFromString(container.Labels)

						dm.EndPointsLock.Lock()
						// if a named endpoint exists we update
						for idx, ep := range dm.EndPoints {
							if container.ContainerName == ep.EndPointName || kl.MatchIdentities(ep.Identities, containerIdentities) {
								endPointEvent = "UPDATED"
								endPointIdx = idx
								endPoint = ep
								break
							}
						}

						switch endPointEvent {
						case "ADDED":
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

							dm.EndPoints = append(dm.EndPoints, endPoint)
						case "UPDATED":
							// in case of AppArmor enforcement when endpoint has to be created first
							endPoint.Containers = append(endPoint.Containers, container.ContainerID)

							// if this container has any additional identities, add them
							endPoint.Identities = append(endPoint.Identities, containerIdentities...)
							endPoint.Identities = slices.Compact(endPoint.Identities)

							// add other policies
							endPoint.SecurityPolicies = []tp.SecurityPolicy{}
							dm.SecurityPoliciesLock.RLock()
							for _, secPol := range dm.SecurityPolicies {
								if kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) {
									endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPol)
								}
							}
							dm.SecurityPoliciesLock.RUnlock()

							dm.EndPoints[endPointIdx] = endPoint
						}
						dm.EndPointsLock.Unlock()
					}

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

							endPoint = dm.EndPoints[idx]

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

					if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
						dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
						if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
							// enforce security policies
							dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
						}
						if dm.Presets != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
							// enforce preset rules
							dm.Presets.UpdateSecurityPolicies(endPoint)
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

		endPoint := tp.EndPoint{}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[containerID]; !ok {
			dm.Containers[containerID] = container
			dm.ContainersLock.Unlock()

			// create/update endpoint in non-k8s mode
			if !dm.K8sEnabled {
				endPointEvent := "ADDED"
				endPointIdx := -1

				containerLabels, containerIdentities := common.GetLabelsFromString(container.Labels)

				dm.EndPointsLock.Lock()
				// if a named endpoint exists we update
				for idx, ep := range dm.EndPoints {
					if container.ContainerName == ep.EndPointName || kl.MatchIdentities(ep.Identities, containerIdentities) {
						endPointEvent = "UPDATED"
						endPointIdx = idx
						endPoint = ep
						break
					}
				}

				switch endPointEvent {
				case "ADDED":
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

					dm.EndPoints = append(dm.EndPoints, endPoint)
				case "UPDATED":
					// in case of AppArmor enforcement when endpoint has to be created first
					endPoint.Containers = append(endPoint.Containers, container.ContainerID)

					// if this container has any additional identities, add them
					endPoint.Identities = append(endPoint.Identities, containerIdentities...)
					endPoint.Identities = slices.Compact(endPoint.Identities)

					// add other policies
					endPoint.SecurityPolicies = []tp.SecurityPolicy{}
					dm.SecurityPoliciesLock.RLock()
					for _, secPol := range dm.SecurityPolicies {
						if kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) {
							endPoint.SecurityPolicies = append(endPoint.SecurityPolicies, secPol)
						}
					}
					dm.SecurityPoliciesLock.RUnlock()

					dm.EndPoints[endPointIdx] = endPoint
				}
				dm.EndPointsLock.Unlock()
			}

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

					if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
						dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
					}

					endPoint = dm.EndPoints[idx]

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
			// for throttling
			dm.SystemMonitor.Logger.ContainerNsKey[containerID] = common.OuterKey{
				MntNs: container.MntNS,
				PidNs: container.PidNS,
			}

			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.RegisterContainer(containerID, container.PidNS, container.MntNS)
			if dm.Presets != nil {
				dm.Presets.RegisterContainer(containerID, container.PidNS, container.MntNS)
			}

			if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endpoint yet
				dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
				if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce security policies
					dm.RuntimeEnforcer.UpdateSecurityPolicies(endPoint)
				}

				if dm.Presets != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
					// enforce preset rules
					dm.Presets.UpdateSecurityPolicies(endPoint)
				}
			}
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
		// delete endpoint if no security rules and containers
		if !dm.K8sEnabled {
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
		}

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
			outkey := dm.SystemMonitor.Logger.ContainerNsKey[containerID]
			dm.Logger.DeleteAlertMapKey(outkey)
			delete(dm.SystemMonitor.Logger.ContainerNsKey, containerID)
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
			if dm.Presets != nil {
				dm.Presets.UnregisterContainer(containerID)
			}
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

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()


	EventChan := Docker.GetEventChannel(ctx, StopChan)

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
				dm.UpdateDockerContainer(msg.ID, string(msg.Action))
			}
		}
	}
}
