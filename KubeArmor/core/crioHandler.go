// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	spec "github.com/opencontainers/runtime-spec/specs-go"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	pb "k8s.io/cri-api/pkg/apis/runtime/v1"
)

// CrioHandler Structure
type CrioHandler struct {
	// connection
	conn *grpc.ClientConn

	// crio client
	client pb.RuntimeServiceClient

	// containers is a map with empty value to have lookups in constant time
	containers map[string]struct{}
}

// CrioContainerInfo struct corresponds to CRI-O's container info returned
// with container status
type CrioContainerInfo struct {
	SandboxID   string    `json:"sandboxID"`
	Pid         int       `json:"pid"`
	RuntimeSpec spec.Spec `json:"runtimeSpec"`
	Privileged  bool      `json:"privileged"`
}

// Crio Handler
var Crio *CrioHandler

// NewCrioHandler Function creates a new Crio handler
func NewCrioHandler() *CrioHandler {
	ch := &CrioHandler{}

	conn, err := grpc.Dial(cfg.GlobalCfg.CRISocket, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil
	}

	ch.conn = conn

	// The runtime service client can be used for all RPCs
	ch.client = pb.NewRuntimeServiceClient(ch.conn)

	ch.containers = make(map[string]struct{})

	return ch
}

// Close the connection
func (ch *CrioHandler) Close() {
	if ch.conn != nil {
		if err := ch.conn.Close(); err != nil {
			kg.Err(err.Error())
		}
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function gets info of a particular container
func (ch *CrioHandler) GetContainerInfo(ctx context.Context, containerID, nodeID string, OwnerInfo map[string]tp.PodOwner) (tp.Container, error) {
	// request to get status of specified container
	// verbose has to be true to retrieve additional CRI specific info
	req := &pb.ContainerStatusRequest{
		ContainerId: containerID,
		Verbose:     true,
	}

	res, err := ch.client.ContainerStatus(ctx, req)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //
	resContainerStatus := res.Status

	container.ContainerID = resContainerStatus.Id
	container.ContainerName = resContainerStatus.Metadata.Name

	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	// check container labels
	containerLabels := resContainerStatus.Labels
	if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
		container.NamespaceName = val
	}
	if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
		container.EndPointName = val
	}

	if len(OwnerInfo) > 0 {
		if podOwnerInfo, ok := OwnerInfo[container.EndPointName]; ok {
			container.Owner = podOwnerInfo
		}
	}

	if !cfg.GlobalCfg.K8sEnv {
		container.NodeName = cfg.GlobalCfg.Host
		container.NodeID = nodeID
	}

	// extracting the runtime specific "info"
	var containerInfo CrioContainerInfo
	err = json.Unmarshal([]byte(res.Info["info"]), &containerInfo)
	if err != nil {
		return tp.Container{}, err
	}

	// path to container's root storage
	container.AppArmorProfile = containerInfo.RuntimeSpec.Process.ApparmorProfile
	container.Privileged = containerInfo.Privileged

	pid := strconv.Itoa(containerInfo.Pid)

	if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, pid, "/ns/pid")); err == nil {
		if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.PidNS); err != nil {
			kg.Warnf("Unable to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	} else {
		return container, err
	}

	if data, err := os.Readlink(filepath.Join(cfg.GlobalCfg.ProcFsMount, pid, "/ns/mnt")); err == nil {
		if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.MntNS); err != nil {
			kg.Warnf("Unable to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
		}
	} else {
		return container, err
	}

	return container, nil
}

// ================= //
// == CRIO Events == //
// ================= //

// GetCrioContainers Function gets IDs of all containers
func (ch *CrioHandler) GetCrioContainers() (map[string]struct{}, error) {
	containers := make(map[string]struct{})
	var err error

	req := pb.ListContainersRequest{}

	if containerList, err := ch.client.ListContainers(context.Background(), &req, grpc.MaxCallRecvMsgSize(kl.DefaultMaxRecvMaxSize)); err == nil {
		for _, container := range containerList.Containers {
			containers[container.Id] = struct{}{}
		}

		return containers, nil
	}

	return nil, err
}

// GetNewCrioContainers Function gets new crio containers
func (ch *CrioHandler) GetNewCrioContainers(containers map[string]struct{}) map[string]struct{} {
	newContainers := make(map[string]struct{})

	for activeContainerID := range containers {
		if _, ok := ch.containers[activeContainerID]; !ok {
			newContainers[activeContainerID] = struct{}{}
		}
	}

	return newContainers
}

// GetDeletedCrioContainers Function gets deleted crio containers
func (ch *CrioHandler) GetDeletedCrioContainers(containers map[string]struct{}) map[string]struct{} {
	deletedContainers := make(map[string]struct{})

	for globalContainerID := range ch.containers {
		if _, ok := containers[globalContainerID]; !ok {
			deletedContainers[globalContainerID] = struct{}{}
			delete(ch.containers, globalContainerID)
		}
	}

	ch.containers = containers

	return deletedContainers
}

// UpdateCrioContainer Function
func (dm *KubeArmorDaemon) UpdateCrioContainer(ctx context.Context, containerID, action string) bool {
	if Crio == nil {
		return false
	}

	if action == "start" {
		// get container info from client
		container, err := Crio.GetContainerInfo(ctx, containerID, dm.Node.NodeID, dm.OwnerInfo)
		if err != nil {
			return false
		}

		if container.ContainerID == "" {
			return false
		}

		endpoint := tp.EndPoint{}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()
		} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
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
			return false
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
			dm.MatchandUpdateContainerSecurityPolicies(containerID)
			dm.EndPointsLock.Unlock()
			dm.ContainersLock.Unlock()
		}

		dm.Logger.Printf("Detected a container (added/%.12s)", containerID)
	} else if action == "destroy" {
		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return false
		}
		if !dm.K8sEnabled {
			dm.EndPointsLock.Lock()
			dm.MatchandRemoveContainerFromEndpoint(containerID)
			dm.EndPointsLock.Unlock()
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
			outkey := dm.SystemMonitor.Logger.ContainerNsKey[containerID]
			dm.Logger.DeleteAlertMapKey(outkey)
			delete(dm.SystemMonitor.Logger.ContainerNsKey, containerID)
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID, container.NamespaceName, container.PidNS, container.MntNS)
			dm.RuntimeEnforcer.UnregisterContainer(containerID)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s)", containerID)
	}

	return true
}

// MonitorCrioEvents Function
func (dm *KubeArmorDaemon) MonitorCrioEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	Crio = NewCrioHandler()

	// check if Crio exists
	if Crio == nil {
		return
	}

	dm.Logger.Print("Started to monitor CRI-O events")

	for {
		select {
		case <-StopChan:
			return

		default:
			containers, err := Crio.GetCrioContainers()
			if err != nil {
				return
			}

			invalidContainers := []string{}

			newContainers := Crio.GetNewCrioContainers(containers)
			deletedContainers := Crio.GetDeletedCrioContainers(containers)

			if len(newContainers) > 0 {
				for containerID := range newContainers {
					if !dm.UpdateCrioContainer(context.Background(), containerID, "start") {
						invalidContainers = append(invalidContainers, containerID)
					}
				}
			}

			for _, invalidContainerID := range invalidContainers {
				delete(Crio.containers, invalidContainerID)
			}

			if len(deletedContainers) > 0 {
				for containerID := range deletedContainers {
					dm.UpdateCrioContainer(context.Background(), containerID, "destroy")
				}
			}
		}

		time.Sleep(time.Millisecond * 50)
	}
}
