// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"time"

	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	pb "github.com/containerd/containerd/api/services/containers/v1"
	pt "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/namespaces"
	"github.com/containerd/typeurl"
	"google.golang.org/grpc"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ======================== //
// == Containerd Handler == //
// ======================== //

// Containerd Handler
var Containerd *ContainerdHandler

// init Function
func init() {
	// Spec -> google.protobuf.Any
	// https://github.com/opencontainers/runtime-spec/blob/master/specs-go/config.go

	const prefix = "types.containerd.io"
	major := strconv.Itoa(specs.VersionMajor)

	typeurl.Register(&specs.Spec{}, prefix, "opencontainers/runtime-spec", major, "Spec")
	typeurl.Register(&specs.Process{}, prefix, "opencontainers/runtime-spec", major, "Process")

	Containerd = NewContainerdHandler()
}

// ContainerdHandler Structure
type ContainerdHandler struct {
	// connection
	conn *grpc.ClientConn

	// container client
	client pb.ContainersClient

	// task client
	taskClient pt.TasksClient

	// context
	containerd context.Context
	docker     context.Context

	// active containers
	containers map[string]context.Context
}

// NewContainerdHandler Function
func NewContainerdHandler() *ContainerdHandler {
	ch := &ContainerdHandler{}

	sockFile := "unix://"

	for _, candidate := range []string{"/var/run/containerd/containerd.sock", "/var/snap/microk8s/common/run/containerd.sock"} {
		if _, err := os.Stat(filepath.Clean(candidate)); err == nil {
			sockFile = sockFile + candidate
			break
		}
	}

	if sockFile == "unix://" {
		return nil
	}

	conn, err := grpc.Dial(sockFile, grpc.WithInsecure())
	if err != nil {
		return nil
	}

	ch.conn = conn

	// container client
	ch.client = pb.NewContainersClient(ch.conn)

	// task client
	ch.taskClient = pt.NewTasksClient(ch.conn)

	// docker namespace
	ch.docker = namespaces.WithNamespace(context.Background(), "moby")

	// containerd namespace
	ch.containerd = namespaces.WithNamespace(context.Background(), "k8s.io")

	// active containers
	ch.containers = map[string]context.Context{}

	return ch
}

// Close Function
func (ch *ContainerdHandler) Close() {
	if ch.conn != nil {
		if err := ch.conn.Close(); err != nil {
			kg.Err(err.Error())
		}
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function
func (ch *ContainerdHandler) GetContainerInfo(ctx context.Context, containerID string) (tp.Container, error) {
	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.client.Get(ctx, &req)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = res.Container.ID
	container.ContainerName = res.Container.ID[:12]

	container.NamespaceName = "Unknown"
	container.ContainerGroupName = "Unknown"

	containerLabels := res.Container.Labels
	if _, ok := containerLabels["io.kubernetes.pod.namespace"]; ok { // kubernetes
		if val, ok := containerLabels["io.kubernetes.pod.namespace"]; ok {
			container.NamespaceName = val
		}
		if val, ok := containerLabels["io.kubernetes.pod.name"]; ok {
			container.ContainerGroupName = val
		}
	}

	iface, err := typeurl.UnmarshalAny(res.Container.Spec)
	if err != nil {
		return tp.Container{}, err
	}

	spec := iface.(*specs.Spec)
	container.AppArmorProfile = spec.Process.ApparmorProfile

	// == //

	taskReq := pt.ListPidsRequest{ContainerID: container.ContainerID}
	if taskRes, err := Containerd.taskClient.ListPids(ctx, &taskReq); err == nil {
		if len(taskRes.Processes) == 0 {
			return container, err
		}

		pid := strconv.Itoa(int(taskRes.Processes[0].Pid))

		if data, err := kl.GetCommandOutputWithErr("readlink", []string{"/proc/" + pid + "/ns/pid"}); err == nil {
			if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.PidNS); err != nil {
				kg.Errf("Failed to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
			}
		}

		if data, err := kl.GetCommandOutputWithErr("readlink", []string{"/proc/" + pid + "/ns/mnt"}); err == nil {
			if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.MntNS); err != nil {
				kg.Errf("Failed to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
			}
		}
	} else {
		return container, err
	}

	// == //

	return container, nil
}

// ======================= //
// == Containerd Events == //
// ======================= //

// GetContainerdContainers Function
func (ch *ContainerdHandler) GetContainerdContainers() map[string]context.Context {
	containers := map[string]context.Context{}

	req := pb.ListContainersRequest{}

	if containerList, err := ch.client.List(ch.docker, &req); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.docker
		}
	}

	if containerList, err := ch.client.List(ch.containerd, &req); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.containerd
		}
	}

	return containers
}

// GetNewContainerdContainers Function
func (ch *ContainerdHandler) GetNewContainerdContainers(containers map[string]context.Context) map[string]context.Context {
	newContainers := map[string]context.Context{}

	for activeContainerID, context := range containers {
		if _, ok := ch.containers[activeContainerID]; !ok {
			newContainers[activeContainerID] = context
		}
	}

	return newContainers
}

// GetDeletedContainerdContainers Function
func (ch *ContainerdHandler) GetDeletedContainerdContainers(containers map[string]context.Context) map[string]context.Context {
	deletedContainers := map[string]context.Context{}

	for globalContainerID := range ch.containers {
		if _, ok := containers[globalContainerID]; !ok {
			delete(ch.containers, globalContainerID)
		}
	}

	ch.containers = containers

	return deletedContainers
}

// UpdateContainerdContainer Function
func (dm *KubeArmorDaemon) UpdateContainerdContainer(ctx context.Context, containerID, action string) bool {
	// check if Containerd exists
	if Containerd == nil {
		return false
	}

	if action == "start" {
		// get container information from containerd client
		container, err := Containerd.GetContainerInfo(ctx, containerID)
		if err != nil {
			return false
		}

		if container.ContainerID == "" {
			return false
		}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()
		} else if dm.Containers[container.ContainerID].PidNS == 0 && dm.Containers[container.ContainerID].MntNS == 0 {
			// this entry was updated by kubernetes before docker detects it
			// thus, we here use the info given by kubernetes instead of the info given by docker

			container.NamespaceName = dm.Containers[container.ContainerID].NamespaceName
			container.ContainerGroupName = dm.Containers[container.ContainerID].ContainerGroupName
			container.ContainerName = dm.Containers[container.ContainerID].ContainerName

			container.PolicyEnabled = dm.Containers[container.ContainerID].PolicyEnabled

			container.ProcessVisibilityEnabled = dm.Containers[container.ContainerID].ProcessVisibilityEnabled
			container.FileVisibilityEnabled = dm.Containers[container.ContainerID].FileVisibilityEnabled
			container.NetworkVisibilityEnabled = dm.Containers[container.ContainerID].NetworkVisibilityEnabled
			container.CapabilitiesVisibilityEnabled = dm.Containers[container.ContainerID].CapabilitiesVisibilityEnabled

			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()

			dm.ContainerGroupsLock.Lock()
			for idx, conGroup := range dm.ContainerGroups {
				if conGroup.NamespaceName == container.NamespaceName && conGroup.ContainerGroupName == container.ContainerGroupName {
					// update containers
					if !kl.ContainsElement(conGroup.Containers, container.ContainerID) {
						dm.ContainerGroups[idx].Containers = append(dm.ContainerGroups[idx].Containers, container.ContainerID)
					}

					// update apparmor profiles
					if !kl.ContainsElement(conGroup.AppArmorProfiles, container.AppArmorProfile) {
						dm.ContainerGroups[idx].AppArmorProfiles = append(dm.ContainerGroups[idx].AppArmorProfiles, container.AppArmorProfile)
					}

					break
				}
			}
			dm.ContainerGroupsLock.Unlock()
		} else {
			dm.ContainersLock.Unlock()
			return false
		}

		if dm.SystemMonitor != nil {
			// update NsMap
			dm.SystemMonitor.AddContainerIDToNsMap(containerID, container.PidNS, container.MntNS)
		}

		dm.LogFeeder.Printf("Detected a container (added/%s)", containerID[:12])

	} else if action == "destroy" {
		dm.ContainersLock.Lock()
		container, ok := dm.Containers[containerID]
		if !ok {
			dm.ContainersLock.Unlock()
			return false
		}
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

		dm.ContainerGroupsLock.Lock()
		for idx, conGroup := range dm.ContainerGroups {
			if conGroup.NamespaceName == container.NamespaceName && conGroup.ContainerGroupName == container.ContainerGroupName {
				// update containers
				for idxC, containerID := range conGroup.Containers {
					if containerID == container.ContainerID {
						dm.ContainerGroups[idx].Containers = append(dm.ContainerGroups[idx].Containers[:idxC], dm.ContainerGroups[idx].Containers[idxC+1:]...)
						break
					}
				}

				// update apparmor profiles
				for idxA, profile := range conGroup.AppArmorProfiles {
					if profile == container.AppArmorProfile {
						dm.ContainerGroups[idx].AppArmorProfiles = append(dm.ContainerGroups[idx].AppArmorProfiles[:idxA], dm.ContainerGroups[idx].AppArmorProfiles[idxA+1:]...)
						break
					}
				}

				break
			}
		}
		dm.ContainerGroupsLock.Unlock()

		if dm.SystemMonitor != nil {
			// update NsMap
			dm.SystemMonitor.DeleteContainerIDFromNsMap(containerID)
		}

		dm.LogFeeder.Printf("Detected a container (removed/%s)", containerID[:12])
	}

	return true
}

// MonitorContainerdEvents Function
func (dm *KubeArmorDaemon) MonitorContainerdEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	// check if Containerd exists
	if Containerd == nil {
		return
	}

	dm.LogFeeder.Print("Started to monitor Containerd events")

	for {
		select {
		case <-StopChan:
			return

		default:
			containers := Containerd.GetContainerdContainers()

			if len(containers) == len(Containerd.containers) {
				time.Sleep(time.Millisecond * 10)
				continue
			}

			invalidContainers := []string{}

			newContainers := Containerd.GetNewContainerdContainers(containers)
			deletedContainers := Containerd.GetDeletedContainerdContainers(containers)

			if len(newContainers) > 0 {
				for containerID, context := range newContainers {
					if !dm.UpdateContainerdContainer(context, containerID, "start") {
						invalidContainers = append(invalidContainers, containerID)
					}
				}
			}

			for _, invalidContainerID := range invalidContainers {
				delete(Containerd.containers, invalidContainerID)
			}

			if len(deletedContainers) > 0 {
				for containerID, context := range deletedContainers {
					dm.UpdateContainerdContainer(context, containerID, "destroy")
				}
			}
		}

		time.Sleep(time.Millisecond * 50)
	}
}
