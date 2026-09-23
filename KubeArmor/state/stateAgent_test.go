// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Authors of KubeArmor

package state

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	tp "github.com/kubearmor/KubeArmor/KubeArmor/types"
	pb "github.com/kubearmor/KubeArmor/protobuf"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/types/known/emptypb"
)

// ── gRPC mock helpers ────────────────────────────────────────────────────────

// baseServerStream satisfies grpc.ServerStream with no-op stubs.
type baseServerStream struct {
	ctx context.Context
}

func (b *baseServerStream) SetHeader(metadata.MD) error  { return nil }
func (b *baseServerStream) SendHeader(metadata.MD) error { return nil }
func (b *baseServerStream) SetTrailer(metadata.MD)       {}
func (b *baseServerStream) Context() context.Context     { return b.ctx }
func (b *baseServerStream) SendMsg(interface{}) error    { return nil }
func (b *baseServerStream) RecvMsg(interface{}) error    { return nil }

// mockWatchStateServer records StateEvents sent through WatchState.
type mockWatchStateServer struct {
	grpc.ServerStream
	base   *baseServerStream
	mu     sync.Mutex
	events []*pb.StateEvent
	sendFn func(*pb.StateEvent) error // optional override
}

func newMockWatchServer(ctx context.Context) *mockWatchStateServer {
	b := &baseServerStream{ctx: ctx}
	return &mockWatchStateServer{ServerStream: b, base: b}
}

func (m *mockWatchStateServer) Send(e *pb.StateEvent) error {
	if m.sendFn != nil {
		return m.sendFn(e)
	}
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
	return nil
}

func (m *mockWatchStateServer) Context() context.Context { return m.base.ctx }

func (m *mockWatchStateServer) received() []*pb.StateEvent {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]*pb.StateEvent, len(m.events))
	copy(cp, m.events)
	return cp
}

// mockGetStateServer records StateEvents batches sent through GetState.
type mockGetStateServer struct {
	grpc.ServerStream
	base   *baseServerStream
	mu     sync.Mutex
	calls  []*pb.StateEvents
	sendFn func(*pb.StateEvents) error
}

func newMockGetServer(ctx context.Context) *mockGetStateServer {
	b := &baseServerStream{ctx: ctx}
	return &mockGetStateServer{ServerStream: b, base: b}
}

func (m *mockGetStateServer) Send(e *pb.StateEvents) error {
	if m.sendFn != nil {
		return m.sendFn(e)
	}
	m.mu.Lock()
	m.calls = append(m.calls, e)
	m.mu.Unlock()
	return nil
}

func (m *mockGetStateServer) Context() context.Context { return m.base.ctx }

// ── shared fixtures (used by both test files) ─────────────────────────────────

func newTestStateAgent() *StateAgent {
	node := &tp.Node{NodeName: "test-node"}
	nodeLock := &sync.RWMutex{}
	containers := map[string]tp.Container{}
	containersLock := &sync.RWMutex{}
	return NewStateAgent(node, nodeLock, containers, containersLock)
}

func testContainer(id, name, ns string) tp.Container {
	return tp.Container{
		ContainerID:   id,
		ContainerName: name,
		NamespaceName: ns,
	}
}

// ── NewStateAgent ─────────────────────────────────────────────────────────────

func TestNewStateAgent_FieldsInitialized(t *testing.T) {
	sa := newTestStateAgent()

	if !sa.Running {
		t.Error("expected Running=true")
	}
	if sa.StateEventChans == nil {
		t.Error("StateEventChans must not be nil")
	}
	if sa.StateEventChansLock == nil {
		t.Error("StateEventChansLock must not be nil")
	}
	if sa.Node == nil || sa.Node.NodeName != "test-node" {
		t.Error("Node not set correctly")
	}
	if sa.Containers == nil {
		t.Error("Containers must not be nil")
	}
	if sa.KubeArmorNamespaces == nil {
		t.Error("KubeArmorNamespaces must not be nil")
	}
}

// ── addStateEventChan / removeStateEventChan ──────────────────────────────────

func TestAddStateEventChan_ReturnsUIDAndChan(t *testing.T) {
	sa := newTestStateAgent()
	uid, ch := sa.addStateEventChan()

	if uid == "" {
		t.Error("expected non-empty UID")
	}
	if ch == nil {
		t.Error("expected non-nil channel")
	}
	if _, ok := sa.StateEventChans[uid]; !ok {
		t.Errorf("UID %s not found in StateEventChans", uid)
	}
}

func TestAddStateEventChan_MultipleCalls_UniqueUIDs(t *testing.T) {
	sa := newTestStateAgent()
	uid1, _ := sa.addStateEventChan()
	uid2, _ := sa.addStateEventChan()

	if uid1 == uid2 {
		t.Error("expected unique UIDs for each call")
	}
	if len(sa.StateEventChans) != 2 {
		t.Errorf("expected 2 channels, got %d", len(sa.StateEventChans))
	}
}

func TestRemoveStateEventChan_DeletesEntry(t *testing.T) {
	sa := newTestStateAgent()
	uid, _ := sa.addStateEventChan()
	sa.removeStateEventChan(uid)

	if _, ok := sa.StateEventChans[uid]; ok {
		t.Errorf("expected UID %s to be removed", uid)
	}
}

// ── DestroyStateAgent ─────────────────────────────────────────────────────────

func TestDestroyStateAgent_SetsRunningFalse(t *testing.T) {
	sa := newTestStateAgent()
	done := make(chan error, 1)
	go func() { done <- sa.DestroyStateAgent() }()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("DestroyStateAgent did not complete in time")
	}

	if sa.Running {
		t.Error("expected Running=false after Destroy")
	}
}

// ── WatchState ────────────────────────────────────────────────────────────────

func TestWatchState_ContextCancel_ReturnsNil(t *testing.T) {
	sa := newTestStateAgent()
	ctx, cancel := context.WithCancel(context.Background())
	srv := newMockWatchServer(ctx)

	done := make(chan error, 1)
	go func() { done <- sa.WatchState(&emptypb.Empty{}, srv) }()

	time.Sleep(20 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("expected nil error on context cancel, got %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("WatchState did not return after context cancellation")
	}
}

func TestWatchState_DeliverEvent_ThenCancel(t *testing.T) {
	sa := newTestStateAgent()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	srv := newMockWatchServer(ctx)

	done := make(chan error, 1)
	go func() { done <- sa.WatchState(&emptypb.Empty{}, srv) }()

	// Wait until WatchState has registered its channel.
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		sa.StateEventChansLock.RLock()
		n := len(sa.StateEventChans)
		sa.StateEventChansLock.RUnlock()
		if n > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}

	sa.PushNodeEvent(tp.Node{NodeName: "worker-1"}, EventAdded)

	// Wait for the event to reach the mock server.
	deadline = time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if len(srv.received()) > 0 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done

	events := srv.received()
	if len(events) == 0 {
		t.Fatal("expected at least one event delivered via WatchState")
	}
	if events[0].Kind != KindNode {
		t.Errorf("expected KindNode, got %s", events[0].Kind)
	}
}

func TestWatchState_StopsWhenRunningFalse(t *testing.T) {
	sa := newTestStateAgent()
	srv := newMockWatchServer(context.Background())

	done := make(chan error, 1)
	go func() { done <- sa.WatchState(&emptypb.Empty{}, srv) }()

	time.Sleep(20 * time.Millisecond)
	sa.Running = false

	// Push a dummy event so the select fires and the loop condition is re-evaluated.
	sa.StateEventChansLock.RLock()
	for _, ch := range sa.StateEventChans {
		ch <- &pb.StateEvent{Kind: KindNode, Type: EventAdded, Name: "dummy"}
	}
	sa.StateEventChansLock.RUnlock()

	select {
	case err := <-done:
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("WatchState did not stop after Running=false")
	}
}

// ── GetState ──────────────────────────────────────────────────────────────────

func TestGetState_SendsNodeAndContainers(t *testing.T) {
	sa := newTestStateAgent()
	sa.Containers["abc123"] = tp.Container{
		ContainerID:   "abc123",
		ContainerName: "web",
		NamespaceName: "production",
	}
	sa.KubeArmorNamespaces["production"] = tp.Namespace{Name: "production", ContainerCount: 1}

	srv := newMockGetServer(context.Background())
	if err := sa.GetState(&emptypb.Empty{}, srv); err != nil {
		t.Fatalf("unexpected error from GetState: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.calls) == 0 {
		t.Fatal("expected at least one Send call from GetState")
	}
	kinds := countKinds(srv.calls[0].StateEvents)
	if kinds[KindNode] != 1 {
		t.Errorf("expected 1 node event, got %d", kinds[KindNode])
	}
	if kinds[KindContainer] != 1 {
		t.Errorf("expected 1 container event, got %d", kinds[KindContainer])
	}
	if kinds[KindNamespace] != 1 {
		t.Errorf("expected 1 namespace event, got %d", kinds[KindNamespace])
	}
}

func TestGetState_EmptyContainers_OnlyNodeSent(t *testing.T) {
	sa := newTestStateAgent()
	srv := newMockGetServer(context.Background())

	if err := sa.GetState(&emptypb.Empty{}, srv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	if len(srv.calls) == 0 {
		t.Fatal("expected a Send call")
	}
	events := srv.calls[0].StateEvents
	if len(events) != 1 || events[0].Kind != KindNode {
		t.Errorf("expected exactly 1 node event, got %v", events)
	}
}

func TestGetState_NodeDataMarshaled(t *testing.T) {
	sa := newTestStateAgent()
	srv := newMockGetServer(context.Background())

	if err := sa.GetState(&emptypb.Empty{}, srv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	nodeEvt := srv.calls[0].StateEvents[0]
	var node tp.Node
	if err := json.Unmarshal(nodeEvt.Object, &node); err != nil {
		t.Fatalf("failed to unmarshal node: %v", err)
	}
	if node.NodeName != "test-node" {
		t.Errorf("expected NodeName=test-node, got %s", node.NodeName)
	}
}

func TestGetState_MultipleContainersAndNamespaces(t *testing.T) {
	sa := newTestStateAgent()
	sa.Containers["c1"] = tp.Container{ContainerID: "c1", ContainerName: "alpha", NamespaceName: "ns-a"}
	sa.Containers["c2"] = tp.Container{ContainerID: "c2", ContainerName: "beta", NamespaceName: "ns-b"}
	sa.KubeArmorNamespaces["ns-a"] = tp.Namespace{Name: "ns-a", ContainerCount: 1}
	sa.KubeArmorNamespaces["ns-b"] = tp.Namespace{Name: "ns-b", ContainerCount: 1}

	srv := newMockGetServer(context.Background())
	if err := sa.GetState(&emptypb.Empty{}, srv); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	srv.mu.Lock()
	defer srv.mu.Unlock()

	kinds := countKinds(srv.calls[0].StateEvents)
	if kinds[KindNode] != 1 {
		t.Errorf("expected 1 node event, got %d", kinds[KindNode])
	}
	if kinds[KindContainer] != 2 {
		t.Errorf("expected 2 container events, got %d", kinds[KindContainer])
	}
	if kinds[KindNamespace] != 2 {
		t.Errorf("expected 2 namespace events, got %d", kinds[KindNamespace])
	}
}

// countKinds tallies event kinds from a slice of StateEvents.
func countKinds(events []*pb.StateEvent) map[string]int {
	m := map[string]int{}
	for _, e := range events {
		m[e.Kind]++
	}
	return m
}
