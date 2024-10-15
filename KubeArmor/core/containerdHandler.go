// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/containerd/typeurl/v2"

	"golang.org/x/exp/slices"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	pb "github.com/containerd/containerd/api/services/containers/v1"
	pt "github.com/containerd/containerd/api/services/tasks/v1"
	"github.com/containerd/containerd/namespaces"
	"google.golang.org/grpc"

	specs "github.com/opencontainers/runtime-spec/specs-go"
)

// ======================== //
// == Containerd Handler == //
// ======================== //

// DefaultCaps contains all the default capabilities given to a
// container by containerd runtime
// Taken from - https://github.com/containerd/containerd/blob/main/oci/spec.go
var defaultCaps = []string{
	"CAP_CHOWN",
	"CAP_DAC_OVERRIDE",
	"CAP_FSETID",
	"CAP_FOWNER",
	"CAP_MKNOD",
	"CAP_NET_RAW",
	"CAP_SETGID",
	"CAP_SETUID",
	"CAP_SETFCAP",
	"CAP_SETPCAP",
	"CAP_NET_BIND_SERVICE",
	"CAP_SYS_CHROOT",
	"CAP_KILL",
	"CAP_AUDIT_WRITE",
}

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

	conn, err := grpc.Dial(cfg.GlobalCfg.CRISocket, grpc.WithInsecure())
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

	kg.Print("Initialized Containerd Handler")

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
func (ch *ContainerdHandler) GetContainerInfo(ctx context.Context, containerID string, OwnerInfo map[string]tp.PodOwner) (tp.Container, error) {
	req := pb.GetContainerRequest{ID: containerID}
	res, err := ch.client.Get(ctx, &req)
	if err != nil {
		return tp.Container{}, err
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = res.Container.ID
	container.ContainerName = res.Container.ID
	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	containerLabels := res.Container.Labels
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

	iface, err := typeurl.UnmarshalAny(res.Container.Spec)
	if err != nil {
		return tp.Container{}, err
	}

	spec := iface.(*specs.Spec)
	container.AppArmorProfile = spec.Process.ApparmorProfile

	// if a container has additional caps than default, we mark it as privileged
	if spec.Process.Capabilities != nil && slices.Compare(spec.Process.Capabilities.Permitted, defaultCaps) >= 0 {
		container.Privileged = true
	}

	// == //

	taskReq := pt.ListPidsRequest{ContainerID: container.ContainerID}
	if taskRes, err := Containerd.taskClient.ListPids(ctx, &taskReq); err == nil {
		if len(taskRes.Processes) == 0 {
			return container, err
		}

		pid := strconv.Itoa(int(taskRes.Processes[0].Pid))

		if data, err := os.Readlink(cfg.GlobalCfg.ProcFsMount + "/" + pid + "/ns/pid"); err == nil {
			if _, err := fmt.Sscanf(data, "pid:[%d]\n", &container.PidNS); err != nil {
				kg.Warnf("Unable to get PidNS (%s, %s, %s)", containerID, pid, err.Error())
			}
		}

		if data, err := os.Readlink(cfg.GlobalCfg.ProcFsMount + "/" + pid + "/ns/mnt"); err == nil {
			if _, err := fmt.Sscanf(data, "mnt:[%d]\n", &container.MntNS); err != nil {
				kg.Warnf("Unable to get MntNS (%s, %s, %s)", containerID, pid, err.Error())
			}
		}
	} else {
		return container, err
	}

	// == //

	if !cfg.GlobalCfg.K8sEnv {
		container.ContainerImage = res.Container.Image //+ kl.GetSHA256ofImage(inspect.Image)

		container.NodeName = cfg.GlobalCfg.Host

		labels := []string{}
		for k, v := range res.Container.Labels {
			labels = append(labels, k+"="+v)
		}
		for k, v := range spec.Annotations {
			labels = append(labels, k+"="+v)
		}

		// for policy matching
		labels = append(labels, "namespaceName="+container.NamespaceName)
		if _, ok := containerLabels["kubearmor.io/container.name"]; !ok {
			labels = append(labels, "kubearmor.io/container.name="+container.ContainerName)
		}

		container.Labels = strings.Join(labels, ",")
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

	if containerList, err := ch.client.List(ch.docker, &req, grpc.MaxCallRecvMsgSize(kl.DefaultMaxRecvMaxSize)); err == nil {
		for _, container := range containerList.Containers {
			containers[container.ID] = ch.docker
		}
	}

	if containerList, err := ch.client.List(ch.containerd, &req, grpc.MaxCallRecvMsgSize(kl.DefaultMaxRecvMaxSize)); err == nil {
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
			deletedContainers[globalContainerID] = context.TODO()
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
		container, err := Containerd.GetContainerInfo(ctx, containerID, dm.OwnerInfo)
		if err != nil {
			return false
		}

		if container.ContainerID == "" {
			return false
		}

		endPoint := tp.EndPoint{}

		dm.ContainersLock.Lock()
		if _, ok := dm.Containers[container.ContainerID]; !ok {
			dm.Containers[container.ContainerID] = container
			dm.ContainersLock.Unlock()

			// create/update endPoint in non-k8s mode
			if !dm.K8sEnabled {
				endPointEvent := "ADDED"
				endPointIdx := -1

				containerLabels, containerIdentities := common.GetLabelsFromString(container.Labels)

				dm.EndPointsLock.Lock()
				// if a named endPoint exists we update
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
					// in case of AppArmor enforcement when endPoint has to be created first
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
					// update containers
					if !kl.ContainsElement(endPoint.Containers, container.ContainerID) { // does not make sense but need to verify
						dm.EndPoints[idx].Containers = append(dm.EndPoints[idx].Containers, container.ContainerID)
					}

					// update apparmor profiles
					if !kl.ContainsElement(endPoint.AppArmorProfiles, container.AppArmorProfile) {
						dm.EndPoints[idx].AppArmorProfiles = append(dm.EndPoints[idx].AppArmorProfiles, container.AppArmorProfile)
					}

					if container.Privileged && dm.EndPoints[idx].PrivilegedContainers != nil {
						dm.EndPoints[idx].PrivilegedContainers[container.ContainerName] = struct{}{}
					}

					// add identities and labels if non-k8s
					if !dm.K8sEnabled {
						labelsSlice := strings.Split(container.Labels, ",")
						for _, label := range labelsSlice {
							key, value, ok := strings.Cut(label, "=")
							if !ok {
								continue
							}

							endPoint.Labels[key] = value
							endPoint.Identities = append(endPoint.Identities, key+"="+value)
						}
					}

					endPoint = dm.EndPoints[idx]

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

			if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endPoint yet
				dm.Logger.UpdateSecurityPolicies("ADDED", endPoint)
				if dm.RuntimeEnforcer != nil && endPoint.PolicyEnabled == tp.KubeArmorPolicyEnabled {
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
			return false
		}
		if !dm.K8sEnabled {
			dm.EndPointsLock.Lock()
			dm.MatchandRemoveContainerFromEndpoint(containerID)
			dm.EndPointsLock.Unlock()
		}
		delete(dm.Containers, containerID)
		dm.ContainersLock.Unlock()

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

		if cfg.GlobalCfg.StateAgent {
			container.Status = "terminated"
			go dm.StateAgent.PushContainerEvent(container, state.EventDeleted)
		}

		dm.Logger.Printf("Detected a container (removed/%.12s/pidns=%d/mntns=%d)", containerID, container.PidNS, container.MntNS)
	}

	return true
}

// MonitorContainerdEvents Function
func (dm *KubeArmorDaemon) MonitorContainerdEvents() {
	dm.WgDaemon.Add(1)
	defer dm.WgDaemon.Done()

	Containerd = NewContainerdHandler()

	// check if Containerd exists
	if Containerd == nil {
		return
	}

	dm.Logger.Print("Started to monitor Containerd events")

	for {
		select {
		case <-StopChan:
			return

		default:
			containers := Containerd.GetContainerdContainers()

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

		time.Sleep(time.Millisecond * 500)
	}
}
