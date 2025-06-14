// SPDX-License-Identifier: Apache-2.0
// Copyright 2021 Authors of KubeArmor

// Package core is responsible for initiating and maintaining interactions between external entities like K8s,CRIs and internal KubeArmor entities like eBPF Monitor and Log Feeders
package core

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/containerd/typeurl/v2"
	"google.golang.org/protobuf/proto"

	"golang.org/x/exp/slices"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	cfg "github.com/kubearmor/KubeArmor/KubeArmor/config"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/state"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"

	"github.com/containerd/containerd/v2/core/events"

	specs "github.com/opencontainers/runtime-spec/specs-go"

	apievents "github.com/containerd/containerd/api/events"
	task "github.com/containerd/containerd/api/services/tasks/v1"
	v2 "github.com/containerd/containerd/v2/client"
	"github.com/containerd/containerd/v2/pkg/namespaces"
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

	// container client
	client *v2.Client

	// context
	containerd context.Context
	docker     context.Context

	k8sEventsCh    <-chan *events.Envelope
	dockerEventsCh <-chan *events.Envelope
}

// NewContainerdHandler Function
func NewContainerdHandler() *ContainerdHandler {
	ch := &ContainerdHandler{}

	// Establish connection to containerd
	client, err := v2.New(strings.TrimPrefix(cfg.GlobalCfg.CRISocket, "unix://"))
	if err != nil {
		kg.Errf("Unable to connect to containerd v2: %v", err)
		return nil
	}
	ch.client = client

	// Subscribe to containerd events

	// docker namespace
	ch.docker = context.Background()
	ch.docker = namespaces.WithNamespace(context.Background(), "moby")

	dockerEventsCh, _ := client.EventService().Subscribe(ch.docker, "")
	ch.dockerEventsCh = dockerEventsCh

	// containerd namespace
	ch.containerd = namespaces.WithNamespace(context.Background(), "k8s.io")

	k8sEventsCh, _ := client.EventService().Subscribe(ch.containerd, "")
	ch.k8sEventsCh = k8sEventsCh

	return ch
}

// Close Function
func (ch *ContainerdHandler) Close() {
	if err := ch.client.Close(); err != nil {
		kg.Err(err.Error())
	}
}

// ==================== //
// == Container Info == //
// ==================== //

// GetContainerInfo Function
func (ch *ContainerdHandler) GetContainerInfo(ctx context.Context, containerID string, eventpid uint32, OwnerInfo map[string]tp.PodOwner) (tp.Container, error) {
	res, err := ch.client.ContainerService().Get(ctx, containerID)
	if err != nil {
		return tp.Container{}, err
	}

	// skip if pause container
	if res.Labels != nil {
		if containerKind, ok := res.Labels["io.cri-containerd.kind"]; ok && containerKind == "sandbox" {
			return tp.Container{}, fmt.Errorf("pause container")
		}
	}

	container := tp.Container{}

	// == container base == //

	container.ContainerID = res.ID
	container.ContainerName = res.ID
	container.NamespaceName = "Unknown"
	container.EndPointName = "Unknown"

	containerLabels := res.Labels
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

	iface, err := typeurl.UnmarshalAny(res.Spec)
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
	if eventpid == 0 {
		taskReq := task.ListPidsRequest{ContainerID: container.ContainerID}
		if taskRes, err := ch.client.TaskService().ListPids(ctx, &taskReq); err == nil {
			if len(taskRes.Processes) == 0 {
				return container, err
			}

			container.Pid = taskRes.Processes[0].Pid

		} else {
			return container, err
		}

	} else {
		container.Pid = eventpid
	}

	pid := strconv.Itoa(int(container.Pid))

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

	taskReq := task.ListPidsRequest{ContainerID: container.ContainerID}
	if taskRes, err := ch.client.TaskService().ListPids(ctx, &taskReq); err == nil {
		if len(taskRes.Processes) == 0 {
			return container, err
		}

		pid := strconv.Itoa(int(taskRes.Processes[0].Pid))

		container.Pid = taskRes.Processes[0].Pid

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
	} else {
		return container, err
	}

	// == //

	if !cfg.GlobalCfg.K8sEnv {
		container.ContainerImage = res.Image //+ kl.GetSHA256ofImage(inspect.Image)

		container.NodeName = cfg.GlobalCfg.Host

		labels := []string{}
		for k, v := range res.Labels {
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

	if containerList, err := ch.client.ContainerService().List(ch.docker); err == nil {
		for _, container := range containerList {
			containers[container.ID] = ch.docker
		}
	} else {
		kg.Err(err.Error())
	}

	if containerList, err := ch.client.ContainerService().List(ch.containerd); err == nil {
		for _, container := range containerList {
			containers[container.ID] = ch.containerd
		}
	} else {
		kg.Err(err.Error())
	}

	return containers
}

// UpdateContainerdContainer Function
func (dm *KubeArmorDaemon) UpdateContainerdContainer(ctx context.Context, containerID string, containerPid uint32, action string) bool {
	// check if Containerd exists
	if Containerd == nil {
		return false
	}

	if action == "start" {
		// get container information from containerd client
		container, err := Containerd.GetContainerInfo(ctx, containerID, containerPid, dm.OwnerInfo)
		if err != nil {
			if strings.Contains(string(err.Error()), "pause container") || strings.Contains(string(err.Error()), "moby") {
				kg.Debug(err.Error())
				return false
			}
			kg.Err(err.Error())
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
						// required only in ADDED event, this alone will update the namespaceList for csp
						updateNamespaceListforCSP(secPol)
						// match ksp || csp
						if (kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(secPol.Spec.Selector, endPoint.Identities)) ||
							(kl.ContainsElement(secPol.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(secPol.Spec.Selector, endPoint.Identities)) {
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
						// match ksp || csp
						if (kl.MatchIdentities(secPol.Spec.Selector.Identities, endPoint.Identities) && kl.MatchExpIdentities(secPol.Spec.Selector, endPoint.Identities)) ||
							(kl.ContainsElement(secPol.Spec.Selector.NamespaceList, endPoint.NamespaceName) && kl.MatchExpIdentities(secPol.Spec.Selector, endPoint.Identities)) {
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
			if dm.Presets != nil {
				dm.Presets.RegisterContainer(container.ContainerID, container.PidNS, container.MntNS)
			}

			if len(endPoint.SecurityPolicies) > 0 { // struct can be empty or no policies registered for the endPoint yet
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
			if dm.Presets != nil {
				dm.Presets.UnregisterContainer(containerID)
			}
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

	containers := Containerd.GetContainerdContainers()

	if len(containers) > 0 {
		for containerID, context := range containers {
			if !dm.UpdateContainerdContainer(context, containerID, 0, "start") {
				continue
			}
		}
	}
	for {
		select {
		case <-StopChan:
			return

		case envelope := <-Containerd.k8sEventsCh:
			dm.handleContainerdEvent(envelope, Containerd.containerd)

		case envelope := <-Containerd.dockerEventsCh:
			dm.handleContainerdEvent(envelope, Containerd.docker)

		}
	}
}

func (dm *KubeArmorDaemon) handleContainerdEvent(envelope *events.Envelope, context context.Context) {
	if envelope == nil {
		return
	}

	// Handle the different event types
	switch envelope.Topic {
	case "/containers/delete":
		deleteContainer := &apievents.ContainerDelete{}

		err := proto.Unmarshal(envelope.Event.GetValue(), deleteContainer)
		if err != nil {
			kg.Errf("failed to unmarshal container's delete event: %v", err)
		}
		dm.UpdateContainerdContainer(context, deleteContainer.GetID(), 0, "destroy")

	case "/tasks/start":
		startTask := &apievents.TaskStart{}

		err := proto.Unmarshal(envelope.Event.GetValue(), startTask)
		if err != nil {
			kg.Errf("failed to unmarshal container's start task: %v", err)
		}
		dm.UpdateContainerdContainer(context, startTask.GetContainerID(), startTask.GetPid(), "start")

	case "/tasks/exit":
		exitTask := &apievents.TaskStart{}

		err := proto.Unmarshal(envelope.Event.GetValue(), exitTask)
		if err != nil {
			kg.Errf("failed to unmarshal container's exit task: %v", err)
		}

		dm.ContainersLock.RLock()
		pid := dm.Containers[exitTask.GetContainerID()].Pid
		dm.ContainersLock.RUnlock()

		if pid == exitTask.GetPid() {
			dm.UpdateContainerdContainer(context, exitTask.GetContainerID(), pid, "destroy")
		}

	}
}
