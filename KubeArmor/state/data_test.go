// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package state

import (
	"encoding/json"
	"testing"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
)

// ── PushContainerEvent ────────────────────────────────────────────────────────

func TestPushContainerEvent_EmptyID_NoOp(t *testing.T) {
	sa := newTestStateAgent()
	sa.PushContainerEvent(tp.Container{NamespaceName: "ns"}, EventAdded)
	if len(sa.KubeArmorNamespaces) != 0 {
		t.Error("namespace should not be created for empty container ID")
	}
}

func TestPushContainerEvent_Add_CreatesNamespace(t *testing.T) {
	sa := newTestStateAgent()
	sa.PushContainerEvent(testContainer("c1", "container1", "ns1"), EventAdded)

	ns, ok := sa.KubeArmorNamespaces["ns1"]
	if !ok {
		t.Fatal("namespace ns1 should have been created")
	}
	if ns.ContainerCount != 1 {
		t.Errorf("expected ContainerCount=1, got %d", ns.ContainerCount)
	}
	if ns.KubearmorFilePosture != "audit" {
		t.Errorf("expected default file posture 'audit', got %s", ns.KubearmorFilePosture)
	}
}

func TestPushContainerEvent_Add_IncrementsExistingNamespace(t *testing.T) {
	sa := newTestStateAgent()
	sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventAdded)
	sa.PushContainerEvent(testContainer("c2", "c2", "ns1"), EventAdded)

	ns := sa.KubeArmorNamespaces["ns1"]
	if ns.ContainerCount != 2 {
		t.Errorf("expected ContainerCount=2, got %d", ns.ContainerCount)
	}
}

func TestPushContainerEvent_Delete_DecrementsCount(t *testing.T) {
	sa := newTestStateAgent()
	sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventAdded)
	sa.PushContainerEvent(testContainer("c2", "c2", "ns1"), EventAdded)
	sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventDeleted)

	ns, ok := sa.KubeArmorNamespaces["ns1"]
	if !ok {
		t.Fatal("namespace ns1 should still exist")
	}
	if ns.ContainerCount != 1 {
		t.Errorf("expected ContainerCount=1, got %d", ns.ContainerCount)
	}
}

func TestPushContainerEvent_Delete_RemovesNamespaceWhenEmpty(t *testing.T) {
	sa := newTestStateAgent()
	sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventAdded)
	sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventDeleted)

	if _, ok := sa.KubeArmorNamespaces["ns1"]; ok {
		t.Error("namespace ns1 should be removed when container count reaches 0")
	}
}

func TestPushContainerEvent_Delete_UnknownNamespace_NoOp(t *testing.T) {
	sa := newTestStateAgent()
	// deleting from a namespace that was never added must not panic
	sa.PushContainerEvent(testContainer("c1", "c1", "ghost"), EventDeleted)
}

func TestPushContainerEvent_NilChans_NoSend(t *testing.T) {
	sa := newTestStateAgent()
	sa.StateEventChans = nil
	// namespace bookkeeping should complete without panicking
	sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventAdded)
}

func TestPushContainerEvent_SendsToRegisteredChan(t *testing.T) {
	sa := newTestStateAgent()
	uid, ch := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	// Pre-seed the namespace so PushContainerEvent doesn't also emit a namespace
	// event that would appear before the container event in the channel.
	sa.KubeArmorNamespaces["ns1"] = tp.Namespace{Name: "ns1", ContainerCount: 1}

	sa.PushContainerEvent(testContainer("c1", "mycontainer", "ns1"), EventAdded)

	select {
	case evt := <-ch:
		if evt.Kind != KindContainer {
			t.Errorf("expected kind=%s, got %s", KindContainer, evt.Kind)
		}
		if evt.Type != EventAdded {
			t.Errorf("expected type=%s, got %s", EventAdded, evt.Type)
		}
		if evt.Name != "mycontainer" {
			t.Errorf("expected name=mycontainer, got %s", evt.Name)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for container event on channel")
	}
}

func TestPushContainerEvent_FullBuffer_DropsGracefully(t *testing.T) {
	sa := newTestStateAgent()
	uid, _ := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	// Fill the buffer (stateEventBufferSize = 25) then push one more.
	for i := 0; i < stateEventBufferSize; i++ {
		sa.PushContainerEvent(testContainer("c1", "c1", "ns1"), EventAdded)
	}
	sa.PushContainerEvent(testContainer("c2", "c2", "ns2"), EventAdded)
}

// ── PushNodeEvent ─────────────────────────────────────────────────────────────

func TestPushNodeEvent_EmptyName_NoOp(t *testing.T) {
	sa := newTestStateAgent()
	uid, ch := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	sa.PushNodeEvent(tp.Node{}, EventAdded)

	select {
	case <-ch:
		t.Error("no event should be sent for empty node name")
	case <-time.After(100 * time.Millisecond):
		// correct: nothing was sent
	}
}

func TestPushNodeEvent_NilChans_NoSend(t *testing.T) {
	sa := newTestStateAgent()
	sa.StateEventChans = nil
	// must not panic
	sa.PushNodeEvent(tp.Node{NodeName: "n1"}, EventAdded)
}

func TestPushNodeEvent_SendsToRegisteredChan(t *testing.T) {
	sa := newTestStateAgent()
	uid, ch := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	sa.PushNodeEvent(tp.Node{NodeName: "worker-1"}, EventAdded)

	select {
	case evt := <-ch:
		if evt.Kind != KindNode {
			t.Errorf("expected kind=%s, got %s", KindNode, evt.Kind)
		}
		if evt.Name != "worker-1" {
			t.Errorf("expected name=worker-1, got %s", evt.Name)
		}
		var decoded tp.Node
		if err := json.Unmarshal(evt.Object, &decoded); err != nil {
			t.Fatalf("failed to unmarshal node: %v", err)
		}
		if decoded.NodeName != "worker-1" {
			t.Errorf("decoded node name mismatch: %s", decoded.NodeName)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for node event")
	}
}

func TestPushNodeEvent_FullBuffer_DropsGracefully(t *testing.T) {
	sa := newTestStateAgent()
	uid, _ := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	for i := 0; i < stateEventBufferSize; i++ {
		sa.PushNodeEvent(tp.Node{NodeName: "n1"}, EventAdded)
	}
	// extra push hits the default (drop) branch
	sa.PushNodeEvent(tp.Node{NodeName: "n1"}, EventAdded)
}

// ── PushNamespaceEvent ────────────────────────────────────────────────────────

func TestPushNamespaceEvent_NilChans_NoSend(t *testing.T) {
	sa := newTestStateAgent()
	sa.StateEventChans = nil
	// must not panic
	sa.PushNamespaceEvent(tp.Namespace{Name: "ns1"}, EventAdded)
}

func TestPushNamespaceEvent_SendsToRegisteredChan(t *testing.T) {
	sa := newTestStateAgent()
	uid, ch := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	sa.PushNamespaceEvent(tp.Namespace{Name: "my-ns", KubearmorFilePosture: "block"}, EventAdded)

	select {
	case evt := <-ch:
		if evt.Kind != KindNamespace {
			t.Errorf("expected kind=%s, got %s", KindNamespace, evt.Kind)
		}
		if evt.Name != "my-ns" {
			t.Errorf("expected name=my-ns, got %s", evt.Name)
		}
		var decoded tp.Namespace
		if err := json.Unmarshal(evt.Object, &decoded); err != nil {
			t.Fatalf("unmarshal error: %v", err)
		}
		if decoded.KubearmorFilePosture != "block" {
			t.Errorf("expected file posture 'block', got %s", decoded.KubearmorFilePosture)
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("timeout waiting for namespace event")
	}
}

func TestPushNamespaceEvent_FullBuffer_DropsGracefully(t *testing.T) {
	sa := newTestStateAgent()
	uid, _ := sa.addStateEventChan()
	defer sa.removeStateEventChan(uid)

	for i := 0; i < stateEventBufferSize; i++ {
		sa.PushNamespaceEvent(tp.Namespace{Name: "ns1"}, EventAdded)
	}
	sa.PushNamespaceEvent(tp.Namespace{Name: "ns1"}, EventAdded)
}
