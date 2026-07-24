// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package state

import (
	"encoding/json"
	"sync"
	"testing"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
)

func newTestAgent() *StateAgent {
	node := &tp.Node{NodeName: "test-node"}
	nodeLock := new(sync.RWMutex)
	containers := make(map[string]tp.Container)
	containersLock := new(sync.RWMutex)
	return NewStateAgent(node, nodeLock, containers, containersLock)
}

func TestNewStateAgent(t *testing.T) {
	node := &tp.Node{NodeName: "node-1"}
	nodeLock := new(sync.RWMutex)
	containers := make(map[string]tp.Container)
	containersLock := new(sync.RWMutex)

	sa := NewStateAgent(node, nodeLock, containers, containersLock)

	if sa == nil {
		t.Fatal("expected non-nil StateAgent")
	}
	if !sa.Running {
		t.Error("expected Running to be true")
	}
	if sa.StateEventChans == nil {
		t.Error("expected StateEventChans to be initialized")
	}
	if sa.Node != node {
		t.Error("expected Node pointer to match")
	}
	if sa.KubeArmorNamespaces == nil {
		t.Error("expected KubeArmorNamespaces to be initialized")
	}
}

func TestDestroyStateAgent(t *testing.T) {
	sa := newTestAgent()
	if err := sa.DestroyStateAgent(); err != nil {
		t.Fatalf("DestroyStateAgent returned error: %v", err)
	}
	if sa.Running {
		t.Error("expected Running to be false after destroy")
	}
}

func TestAddRemoveStateEventChan(t *testing.T) {
	sa := newTestAgent()

	uid, ch := sa.addStateEventChan()
	if uid == "" {
		t.Fatal("expected non-empty uid")
	}
	if ch == nil {
		t.Fatal("expected non-nil channel")
	}
	if cap(ch) != stateEventBufferSize {
		t.Errorf("expected buffer size %d, got %d", stateEventBufferSize, cap(ch))
	}

	sa.StateEventChansLock.RLock()
	_, ok := sa.StateEventChans[uid]
	sa.StateEventChansLock.RUnlock()
	if !ok {
		t.Error("channel should be present in StateEventChans")
	}

	sa.removeStateEventChan(uid)

	sa.StateEventChansLock.RLock()
	_, ok = sa.StateEventChans[uid]
	sa.StateEventChansLock.RUnlock()
	if ok {
		t.Error("channel should be removed from StateEventChans after remove")
	}
}

func TestPushContainerEvent(t *testing.T) {
	t.Run("EmptyContainerID", func(t *testing.T) {
		sa := newTestAgent()
		sa.PushContainerEvent(tp.Container{}, EventAdded)
	})

	t.Run("NilChans", func(t *testing.T) {
		sa := newTestAgent()
		sa.StateEventChans = nil
		sa.PushContainerEvent(tp.Container{ContainerID: "c1", ContainerName: "nginx", NamespaceName: "default"}, EventAdded)
	})

	t.Run("AddedCreatesNamespace", func(t *testing.T) {
		sa := newTestAgent()
		ch := make(chan *pb.StateEvent, 10)
		sa.StateEventChans["uid1"] = ch

		sa.PushContainerEvent(tp.Container{ContainerID: "c1", ContainerName: "nginx", NamespaceName: "production"}, EventAdded)

		nsEvent := <-ch
		if nsEvent.Kind != KindNamespace {
			t.Errorf("expected namespace event first, got %s", nsEvent.Kind)
		}
		if nsEvent.Type != EventAdded {
			t.Errorf("expected added type, got %s", nsEvent.Type)
		}
		if nsEvent.Name != "production" {
			t.Errorf("expected name 'production', got %s", nsEvent.Name)
		}

		cEvent := <-ch
		if cEvent.Kind != KindContainer {
			t.Errorf("expected container event, got %s", cEvent.Kind)
		}
		if cEvent.Name != "nginx" {
			t.Errorf("expected name 'nginx', got %s", cEvent.Name)
		}

		sa.KubeArmorNamespacesLock.RLock()
		ns, ok := sa.KubeArmorNamespaces["production"]
		sa.KubeArmorNamespacesLock.RUnlock()
		if !ok {
			t.Fatal("expected namespace 'production' to exist")
		}
		if ns.ContainerCount != 1 {
			t.Errorf("expected ContainerCount 1, got %d", ns.ContainerCount)
		}
	})

	t.Run("AddedIncrementsExistingNamespace", func(t *testing.T) {
		sa := newTestAgent()
		ch := make(chan *pb.StateEvent, 10)
		sa.StateEventChans["uid1"] = ch

		sa.PushContainerEvent(tp.Container{ContainerID: "c1", ContainerName: "nginx", NamespaceName: "default"}, EventAdded)
		<-ch // ns event
		<-ch // container event

		sa.PushContainerEvent(tp.Container{ContainerID: "c2", ContainerName: "redis", NamespaceName: "default"}, EventAdded)
		cEvent := <-ch
		if cEvent.Kind != KindContainer {
			t.Errorf("expected container event, got %s", cEvent.Kind)
		}

		sa.KubeArmorNamespacesLock.RLock()
		ns := sa.KubeArmorNamespaces["default"]
		sa.KubeArmorNamespacesLock.RUnlock()
		if ns.ContainerCount != 2 {
			t.Errorf("expected ContainerCount 2, got %d", ns.ContainerCount)
		}
	})

	t.Run("DeletedDecrementsCount", func(t *testing.T) {
		sa := newTestAgent()
		ch := make(chan *pb.StateEvent, 10)
		sa.StateEventChans["uid1"] = ch

		sa.PushContainerEvent(tp.Container{ContainerID: "c1", ContainerName: "nginx", NamespaceName: "default"}, EventAdded)
		sa.PushContainerEvent(tp.Container{ContainerID: "c2", ContainerName: "redis", NamespaceName: "default"}, EventAdded)
		<-ch
		<-ch
		<-ch // ns-added, c1-added, c2-added

		sa.PushContainerEvent(tp.Container{ContainerID: "c1", ContainerName: "nginx", NamespaceName: "default"}, EventDeleted)
		cEvent := <-ch
		if cEvent.Kind != KindContainer || cEvent.Type != EventDeleted {
			t.Errorf("expected deleted container event, got kind=%s type=%s", cEvent.Kind, cEvent.Type)
		}

		sa.KubeArmorNamespacesLock.RLock()
		ns, ok := sa.KubeArmorNamespaces["default"]
		sa.KubeArmorNamespacesLock.RUnlock()
		if !ok {
			t.Fatal("namespace should still exist with one container remaining")
		}
		if ns.ContainerCount != 1 {
			t.Errorf("expected ContainerCount 1, got %d", ns.ContainerCount)
		}
	})

	t.Run("DeletedLastContainerRemovesNamespace", func(t *testing.T) {
		sa := newTestAgent()
		ch := make(chan *pb.StateEvent, 10)
		sa.StateEventChans["uid1"] = ch

		c := tp.Container{ContainerID: "c1", ContainerName: "nginx", NamespaceName: "staging"}
		sa.PushContainerEvent(c, EventAdded)
		<-ch // ns-added
		<-ch // c-added

		sa.PushContainerEvent(c, EventDeleted)

		nsEvent := <-ch
		if nsEvent.Kind != KindNamespace || nsEvent.Type != EventDeleted {
			t.Errorf("expected namespace deleted event, got kind=%s type=%s", nsEvent.Kind, nsEvent.Type)
		}
		cEvent := <-ch
		if cEvent.Kind != KindContainer || cEvent.Type != EventDeleted {
			t.Errorf("expected container deleted event, got kind=%s type=%s", cEvent.Kind, cEvent.Type)
		}

		sa.KubeArmorNamespacesLock.RLock()
		_, ok := sa.KubeArmorNamespaces["staging"]
		sa.KubeArmorNamespacesLock.RUnlock()
		if ok {
			t.Error("namespace 'staging' should have been deleted")
		}
	})
}

func TestPushNodeEvent(t *testing.T) {
	t.Run("EmptyNodeName", func(t *testing.T) {
		sa := newTestAgent()
		sa.PushNodeEvent(tp.Node{}, EventAdded)
	})

	t.Run("NilChans", func(t *testing.T) {
		sa := newTestAgent()
		sa.StateEventChans = nil
		sa.PushNodeEvent(tp.Node{NodeName: "node-1"}, EventAdded)
	})

	t.Run("SendsNodeEvent", func(t *testing.T) {
		sa := newTestAgent()
		ch := make(chan *pb.StateEvent, 5)
		sa.StateEventChans["uid1"] = ch

		sa.PushNodeEvent(tp.Node{NodeName: "node-1"}, EventAdded)

		event := <-ch
		if event.Kind != KindNode {
			t.Errorf("expected kind %s, got %s", KindNode, event.Kind)
		}
		if event.Type != EventAdded {
			t.Errorf("expected type %s, got %s", EventAdded, event.Type)
		}
		if event.Name != "node-1" {
			t.Errorf("expected name 'node-1', got %s", event.Name)
		}

		var node tp.Node
		if err := json.Unmarshal(event.Object, &node); err != nil {
			t.Fatalf("failed to unmarshal node object: %v", err)
		}
		if node.NodeName != "node-1" {
			t.Errorf("expected NodeName 'node-1', got %s", node.NodeName)
		}
	})
}

func TestPushNamespaceEvent(t *testing.T) {
	t.Run("NilChans", func(t *testing.T) {
		sa := newTestAgent()
		sa.StateEventChans = nil
		sa.PushNamespaceEvent(tp.Namespace{Name: "ns-1"}, EventAdded)
	})

	t.Run("SendsNamespaceEvent", func(t *testing.T) {
		sa := newTestAgent()
		ch := make(chan *pb.StateEvent, 5)
		sa.StateEventChans["uid1"] = ch

		ns := tp.Namespace{Name: "kube-system", KubearmorFilePosture: "audit"}
		sa.PushNamespaceEvent(ns, EventAdded)

		event := <-ch
		if event.Kind != KindNamespace {
			t.Errorf("expected kind %s, got %s", KindNamespace, event.Kind)
		}
		if event.Type != EventAdded {
			t.Errorf("expected type %s, got %s", EventAdded, event.Type)
		}
		if event.Name != "kube-system" {
			t.Errorf("expected name 'kube-system', got %s", event.Name)
		}
	})

	t.Run("BroadcastsToAllClients", func(t *testing.T) {
		sa := newTestAgent()
		ch1 := make(chan *pb.StateEvent, 5)
		ch2 := make(chan *pb.StateEvent, 5)
		sa.StateEventChans["uid1"] = ch1
		sa.StateEventChans["uid2"] = ch2

		sa.PushNamespaceEvent(tp.Namespace{Name: "default"}, EventUpdated)

		e1 := <-ch1
		e2 := <-ch2
		if e1.Kind != KindNamespace || e2.Kind != KindNamespace {
			t.Error("expected both clients to receive namespace event")
		}
		if e1.Type != EventUpdated || e2.Type != EventUpdated {
			t.Error("expected updated type on both clients")
		}
	})
}
