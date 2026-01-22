// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

// package state implements the state agent service which reports details about the node and containers being protected by KubeArmor
package state

import (
	"encoding/json"
	"sync"
	"time"

	"github.com/google/uuid"
	kl "github.com/kubearmor/KubeArmor/KubeArmor/common"
	kg "github.com/kubearmor/KubeArmor/KubeArmor/log"
	"github.com/kubearmor/KubeArmor/KubeArmor/types"
	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	stateEventBufferSize = 25

	// EventAdded denotes an add event
	EventAdded = "added"
	// EventUpdated denotes an update event
	EventUpdated = "updated"
	// EventDeleted denotes an delete event
	EventDeleted = "deleted"

	// KindContainer denotes a container kind
	KindContainer = "container"
	// KindPod denotes a pod kind
	KindPod = "pod"
	// KindNode denotes a node kind
	KindNode = "node"
	// KindNamespace denotes a namespace kind
	KindNamespace = "namespace"
)

// StateAgent reports the state of containers/nodes protected by KubeArmor
type StateAgent struct {
	Running bool

	StateEventChans     map[string]chan *pb.StateEvent
	StateEventChansLock *sync.RWMutex

	Node     *tp.Node
	NodeLock *sync.RWMutex

	Containers     map[string]tp.Container
	ContainersLock *sync.RWMutex

	KubeArmorNamespaces     map[string]types.Namespace
	KubeArmorNamespacesLock *sync.RWMutex
}

// NewStateAgent returns a new initialized state agent
func NewStateAgent(node *tp.Node, nodeLock *sync.RWMutex, containers map[string]tp.Container, containersLock *sync.RWMutex) *StateAgent {
	return &StateAgent{
		Running: true,

		StateEventChans:     make(map[string]chan *pb.StateEvent),
		StateEventChansLock: new(sync.RWMutex),

		Node:     node,
		NodeLock: nodeLock,

		Containers:     containers,
		ContainersLock: containersLock,

		KubeArmorNamespaces:     make(map[string]tp.Namespace),
		KubeArmorNamespacesLock: new(sync.RWMutex),
	}
}

// add new channel for broadcast
func (sa *StateAgent) addStateEventChan() (string, chan *pb.StateEvent) {
	uid := uuid.Must(uuid.NewRandom()).String()
	conn := make(chan *pb.StateEvent, stateEventBufferSize)

	sa.StateEventChansLock.Lock()
	sa.StateEventChans[uid] = conn
	sa.StateEventChansLock.Unlock()

	return uid, conn
}

// close chan and delete connection
func (sa *StateAgent) removeStateEventChan(uid string) {
	sa.StateEventChansLock.Lock()
	close(sa.StateEventChans[uid])
	delete(sa.StateEventChans, uid)
	sa.StateEventChansLock.Unlock()
}

// WatchState sends state events in a continuous stream
func (sa *StateAgent) WatchState(msg *emptypb.Empty, srv pb.StateAgent_WatchStateServer) error {
	uid, conn := sa.addStateEventChan()
	kg.Printf("Added a new client (%s) for WatchState", uid)

	defer func() {
		sa.removeStateEventChan(uid)
		kg.Printf("Deleted client (%s) for WatchState", uid)
	}()

	for sa.Running {
		select {
		case <-srv.Context().Done():
			return nil
		case event := <-conn:
			if err := kl.HandleGRPCErrors(srv.Send(event)); err != nil {
				kg.Warnf("Failed to send state event to WatchState client %s: %s", uid, err.Error())
				return err
			}
		}
	}

	return nil
}

// GetState sends current state upon request
func (sa *StateAgent) GetState(msg *emptypb.Empty, srv pb.StateAgent_GetStateServer) error {
	stateEventList := make([]*pb.StateEvent, 0)

	nodeData, err := json.Marshal(sa.Node)
	if err != nil {
		kg.Warnf("Error while trying to marshal node data: %s", err.Error())
	}

	nodeEvent := &pb.StateEvent{
		Kind:   KindNode,
		Type:   EventAdded,
		Name:   sa.Node.NodeName,
		Object: nodeData,
	}
	stateEventList = append(stateEventList, nodeEvent)

	sa.KubeArmorNamespacesLock.RLock()
	for nsName, ns := range sa.KubeArmorNamespaces {
		nsBytes, err := json.Marshal(ns)
		if err != nil {
			kg.Warnf("Failed to marshal ns %s event: %s", nsName, err.Error())
		}

		nsEvent := &pb.StateEvent{
			Kind:   KindNamespace,
			Type:   EventAdded,
			Name:   nsName,
			Object: nsBytes,
		}

		stateEventList = append(stateEventList, nsEvent)
	}
	sa.KubeArmorNamespacesLock.RUnlock()

	for _, container := range sa.Containers {
		containerBytes, err := json.Marshal(container)
		if err != nil {
			kg.Warnf("Error while trying to marshal container %.6s data: %s", container.ContainerID, err.Error())
		}

		containerEvent := &pb.StateEvent{
			Kind:   KindContainer,
			Type:   EventAdded,
			Name:   container.ContainerName,
			Object: containerBytes,
		}

		stateEventList = append(stateEventList, containerEvent)
	}

	stateEvents := &pb.StateEvents{
		StateEvents: stateEventList,
	}

	err = srv.Send(stateEvents)
	if err := kl.HandleGRPCErrors(err); err != nil {
		kg.Warnf("Failed to send state events to GetState: ", err.Error())
		return err
	}

	return nil
}

// DestroyStateAgent destroys the referenced state agent
func (sa *StateAgent) DestroyStateAgent() error {
	sa.Running = false
	time.Sleep(1 * time.Second)

	return nil
}
