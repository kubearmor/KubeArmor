// SPDX-License-Identifier: Apache-2.0
// Copyright 2023 Authors of KubeArmor

package state

import (
	"encoding/json"

	"github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

// pushes (container + pod) & workload event
func (sa *StateAgent) PushContainerEvent(container tp.Container, event string) {
	if container.ContainerID == "" {
		kg.Debug("Error while pushing container event. Missing data.")
		return
	}

	// create ns first
	namespace := container.NamespaceName
	sa.KubeArmorNamespacesLock.Lock()
	if event == EventAdded {

		// create this kubearmor ns if it doesn't exist
		// currently only "container_namespace" until we have config agent
		if _, ok := sa.KubeArmorNamespaces[namespace]; !ok {
			sa.KubeArmorNamespaces[namespace] = []string{}
			sa.KubeArmorNamespaces[namespace] = append(sa.KubeArmorNamespaces[container.NamespaceName], container.ContainerID)

			sa.PushNamespaceEvent(namespace, EventAdded)
		} else {
			sa.KubeArmorNamespaces[namespace] = append(sa.KubeArmorNamespaces[container.NamespaceName], container.ContainerID)
		}

	} else if event == EventDeleted {

		if containers, ok := sa.KubeArmorNamespaces[namespace]; ok {
			containerDeleted := false
			for i, c := range containers {
				if c == container.ContainerID {
					newNSList := common.RemoveStringElement(containers, i)
					sa.KubeArmorNamespaces[namespace] = newNSList
					break
				}
			}

			// no containers left - namespace deleted
			if containerDeleted && len(sa.KubeArmorNamespaces[namespace]) > 0 {
				sa.PushNamespaceEvent(namespace, EventDeleted)
			}
		}

	}
	sa.KubeArmorNamespacesLock.Unlock()

	containerBytes, err := json.Marshal(container)
	if err != nil {
		kg.Warnf("Error while trying to marshal container data. %s", err.Error())
		return
	}

	containerEvent := &pb.StateEvent{
		Kind:   KindContainer,
		Type:   event,
		Name:   container.ContainerName,
		Object: containerBytes,
	}

	// skip sending message as no state receiver is connected
	if sa.StateEvents == nil {
		return
	}

	select {
	case sa.StateEvents <- containerEvent:
	default:
		kg.Debugf("Failed to send container %s state event", event)
		return
	}

	return
}

func (sa *StateAgent) PushNodeEvent(node tp.Node, event string) {
	if node.NodeName == "" {
		kg.Warn("Received empty node event")
		return
	}

	nodeData, err := json.Marshal(node)
	if err != nil {
		kg.Warnf("Error while trying to marshal node data. %s", err.Error())
		return
	}

	nodeEvent := &pb.StateEvent{
		Kind:   KindNode,
		Type:   event,
		Name:   node.NodeName,
		Object: nodeData,
	}

	// skip sending message as no state receiver is connected
	if sa.StateEvents == nil {
		return
	}

	select {
	case sa.StateEvents <- nodeEvent:
	default:
		kg.Debugf("Failed to send node %s state event.", event)
		return
	}

	return
}

func (sa *StateAgent) PushNamespaceEvent(namespace string, event string) {
	ns := types.Namespace{
		Name: namespace,
		//Labels: "",
		KubearmorFilePosture: "audit",
		KubearmorNetworkPosture: "audit",
	}

	nsBytes, err := json.Marshal(ns)
	if err != nil {
		kg.Warnf("Failed to marshal ns event: %s", err.Error())
		return
	}

	nsEvent := &pb.StateEvent{
		Kind:   KindNamespace,
		Type:   event,
		Name:   namespace,
		Object: nsBytes,
	}

	// skip sending message as no state receiver is connected
	if sa.StateEvents == nil {
		return
	}

	select {
	case sa.StateEvents <- nsEvent:
	default:
		kg.Debugf("Failed to send namespace %s state event", event)
		return
	}
}
